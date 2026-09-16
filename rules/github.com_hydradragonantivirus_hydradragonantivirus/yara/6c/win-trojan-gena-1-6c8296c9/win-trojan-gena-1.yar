rule Win_Trojan_Gena_1
{
strings:
	$a0 = { d6005053515206b80103b90100ba0000bb00000e079c2eff1ed600075a595b589debda }


condition:
	$a0
}