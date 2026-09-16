rule Win_Trojan_Trojan_150
{
strings:
	$a0 = { 045850488ed8291e1200291e0300be74 }


condition:
	$a0
}