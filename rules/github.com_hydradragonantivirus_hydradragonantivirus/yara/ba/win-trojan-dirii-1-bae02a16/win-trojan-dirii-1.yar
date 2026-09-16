rule Win_Trojan_DirII_1
{
strings:
	$a0 = { 4018ff8b7813c74013e9048c4815 }


condition:
	$a0
}