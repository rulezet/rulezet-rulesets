rule Win_Trojan_Leprosy_50
{
strings:
	$a0 = { 8a273226060188279090904381fb82047eeec3 }


condition:
	$a0
}