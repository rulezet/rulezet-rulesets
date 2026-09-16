rule Win_Trojan_Sister_2
{
strings:
	$a0 = { 1e70008c067200fb33c08ed8b84953a340032e80bc }


condition:
	$a0
}