rule Win_Trojan_Philis_139
{
strings:
	$a0 = { 515183c404893424575383c404568b3c }


condition:
	$a0
}