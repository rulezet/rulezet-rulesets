rule Win_Trojan_CorporateLife_9
{
strings:
	$a0 = { 06900efb1f404090ba2b074890fb90bf3e0190803523fbfb48fb479040904a75f24848fb90fb40fb40409090fbfb }


condition:
	$a0
}