rule Win_Trojan_Shel_1
{
strings:
	$a0 = { 535157561e065281c292008edabfb70390a02a0330852f014feb0079f7 }


condition:
	$a0
}