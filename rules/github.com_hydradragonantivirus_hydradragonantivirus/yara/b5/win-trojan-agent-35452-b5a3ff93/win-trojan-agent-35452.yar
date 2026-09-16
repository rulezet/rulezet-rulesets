rule Win_Trojan_Agent_35452
{
strings:
	$a0 = { 66696c655f5f3b245f78 }

	$a1 = { 63693871666e352b666e352b }


condition:
	$a0 and $a1
}