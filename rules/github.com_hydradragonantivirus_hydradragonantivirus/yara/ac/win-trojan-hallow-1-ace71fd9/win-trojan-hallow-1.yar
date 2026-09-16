rule Win_Trojan_Hallow_1
{
strings:
	$a0 = { 0175f65d5581ed03008db60300b9e9002e8134 }


condition:
	$a0
}