rule Win_Trojan_MIX2_1
{
strings:
	$a0 = { 8cc803c650b8260050cb55508cc0e8 }


condition:
	$a0
}