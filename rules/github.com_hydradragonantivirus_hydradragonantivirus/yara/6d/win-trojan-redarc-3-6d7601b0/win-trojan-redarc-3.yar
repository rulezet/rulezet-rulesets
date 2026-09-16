rule Win_Trojan_Redarc_3
{
strings:
	$a0 = { 06e800001e07975d83ed06bb0011b44acd217306071f610e56cbb89f0103c5b104d3e8401e5b }


condition:
	$a0
}