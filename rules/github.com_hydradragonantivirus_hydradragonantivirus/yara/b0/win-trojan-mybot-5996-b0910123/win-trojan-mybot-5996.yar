rule Win_Trojan_Mybot_5996
{
strings:
	$a0 = { b7d4dc46d1ba58b2b4b748afeb54004362492550b2aca0592c080a5d2dd0110d24851b9bdb16946b1626b28f9fee58fff2f99cfee77c13f74fef05ce6cce51f74ce4ccf05ce99e259d33a3a67867ee9fba5e }


condition:
	$a0
}