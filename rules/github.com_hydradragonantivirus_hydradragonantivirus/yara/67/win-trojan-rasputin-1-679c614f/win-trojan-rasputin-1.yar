rule Win_Trojan_Rasputin_1
{
strings:
	$a0 = { 300446e2fbc3fa33c08ed0bcfc7bfb8ed8be667cb95600e8e4ff }


condition:
	$a0
}