rule Win_Trojan_Trivial_334
{
strings:
	$a0 = { ba2301cd217227b8023dba9e00cd21b740ba00019388e1cd21b43ecd21b44febdf }


condition:
	$a0
}