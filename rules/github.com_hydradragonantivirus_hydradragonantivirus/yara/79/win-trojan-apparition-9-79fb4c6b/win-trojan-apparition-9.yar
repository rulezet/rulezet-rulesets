rule Win_Trojan_Apparition_9
{
strings:
	$a0 = { 81ee????b8ac0fcd213d353575 }


condition:
	$a0
}