rule Win_Trojan_VTech_1
{
strings:
	$a0 = { 24f6dcf6d42e88244681fe370b75efbf2f002e80351d4781ff370b740d2e80351d4781ff370b }


condition:
	$a0
}