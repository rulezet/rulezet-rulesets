rule Win_Trojan_Miny_6
{
strings:
	$a0 = { 57cd215152b04033d2b9f401e83bffb000e8bb00b040baf301b90400e82bff5a59b80157cd21 }


condition:
	$a0
}