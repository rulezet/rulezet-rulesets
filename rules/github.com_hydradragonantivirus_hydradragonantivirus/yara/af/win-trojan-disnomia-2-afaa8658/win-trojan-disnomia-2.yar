rule Win_Trojan_Disnomia_2
{
strings:
	$a0 = { b9ed02be????2e310483c60240e2f7 }


condition:
	$a0
}