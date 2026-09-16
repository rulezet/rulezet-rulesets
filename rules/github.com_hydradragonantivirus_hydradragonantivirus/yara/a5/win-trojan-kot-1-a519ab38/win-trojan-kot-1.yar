rule Win_Trojan_Kot_1
{
strings:
	$a0 = { 4b74069dea420abe17061e505351525633dbe86d018b }


condition:
	$a0
}