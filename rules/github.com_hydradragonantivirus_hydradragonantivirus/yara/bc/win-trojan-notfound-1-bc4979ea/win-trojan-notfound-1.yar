rule Win_Trojan_NotFound_1
{
strings:
	$a0 = { 69732e2e2e0a0d01209a00007c00c80202008dbe00ff16 }


condition:
	$a0
}