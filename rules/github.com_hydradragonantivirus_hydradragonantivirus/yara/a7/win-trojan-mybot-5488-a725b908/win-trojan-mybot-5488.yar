rule Win_Trojan_Mybot_5488
{
strings:
	$a0 = { 54ace8b9e8e57f74a6284e4954d04bbb43272088df94156a38e3a91733f6eeeeabab99d789ae9b2bdd9e61d7e92e99dd77cf95a5a31f9f83a4d110301b47b3150071415629ab }


condition:
	$a0
}