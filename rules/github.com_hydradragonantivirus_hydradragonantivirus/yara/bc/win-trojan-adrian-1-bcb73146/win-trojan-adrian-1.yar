rule Win_Trojan_Adrian_1
{
strings:
	$a0 = { 8bfc368b2d81ed03012e803e5b01b97455b933048dbe5b01ba0100 }


condition:
	$a0
}