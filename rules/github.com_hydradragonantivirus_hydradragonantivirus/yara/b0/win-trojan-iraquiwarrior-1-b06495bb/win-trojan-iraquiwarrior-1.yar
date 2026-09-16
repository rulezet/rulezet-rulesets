rule Win_Trojan_IraquiWarrior_1
{
strings:
	$a0 = { 90ba2803fc908bf29083c60a90bf00 }


condition:
	$a0
}