rule Win_Trojan_Vgen_15
{
strings:
	$a0 = { e800005d83ed031e33c08ed8c41e040026803fcf741426c607cfb88003ba8000b90100b88103ff2e64000e1f0e07fc2e }


condition:
	$a0
}