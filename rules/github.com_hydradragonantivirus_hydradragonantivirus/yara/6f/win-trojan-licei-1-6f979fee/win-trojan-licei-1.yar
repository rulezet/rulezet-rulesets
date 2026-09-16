rule Win_Trojan_Licei_1
{
strings:
	$a0 = { e800005e83ee??1e505351b98d01bb23002e8a64222e322601002e302043e2f1 }


condition:
	$a0
}