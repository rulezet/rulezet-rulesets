rule Win_Trojan_Gen_175
{
strings:
	$a0 = { c3032a2e2a9a000038005589e5e8d0febf61020e57b8370050bfd00e1e579a42002c00833e }


condition:
	$a0
}