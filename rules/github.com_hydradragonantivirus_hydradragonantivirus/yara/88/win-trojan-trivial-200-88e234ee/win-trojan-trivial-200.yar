rule Win_Trojan_Trivial_200
{
strings:
	$a0 = { 4eba1f01cd21b8023dba9e00cd2193720cb440b1258bd6cd21b44febe7c32a2e636f6d }


condition:
	$a0
}