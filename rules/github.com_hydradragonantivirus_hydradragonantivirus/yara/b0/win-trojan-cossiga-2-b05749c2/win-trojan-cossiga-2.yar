rule Win_Trojan_Cossiga_2
{
strings:
	$a0 = { 83e10fbb10002bd953f88b551c03c383d200b91000f7 }


condition:
	$a0
}