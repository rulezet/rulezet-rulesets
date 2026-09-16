rule Win_Trojan_VGEN_147
{
strings:
	$a0 = { da009a000065005589e5b800029a7c02da0081ec0002bfd4010e57bf44021e57b8ff00509ac306da00a12e018b }


condition:
	$a0
}