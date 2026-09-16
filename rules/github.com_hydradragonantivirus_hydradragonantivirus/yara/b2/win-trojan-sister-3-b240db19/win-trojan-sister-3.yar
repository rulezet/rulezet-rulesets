rule Win_Trojan_Sister_3
{
strings:
	$a0 = { 891e70008c06720033c08ed8b84953a340032e80bc }


condition:
	$a0
}