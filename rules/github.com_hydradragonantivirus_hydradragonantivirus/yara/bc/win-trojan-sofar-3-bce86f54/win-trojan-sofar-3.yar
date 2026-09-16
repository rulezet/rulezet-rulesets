rule Win_Trojan_SoFar_3
{
strings:
	$a0 = { 50535157561e065281c217008edabfbc0390a02c0330852f014feb0079f7 }


condition:
	$a0
}