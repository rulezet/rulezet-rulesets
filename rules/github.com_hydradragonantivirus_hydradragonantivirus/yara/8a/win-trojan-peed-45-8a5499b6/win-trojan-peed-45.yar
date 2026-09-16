rule Win_Trojan_Peed_45
{
strings:
	$a0 = { 89c189e58b6d1c83ed5f83ed644809ed75f8bf28????0201c101f95189ceb9 }


condition:
	$a0
}