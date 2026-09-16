rule Win_Trojan_VDL_1
{
strings:
	$a0 = { 26110180fc0a723232e488261101b80006b70733c9ba4f18cd10b40232ff33d2cd10fcbe12018b0ecd01ac34feb40e }


condition:
	$a0
}