rule Win_Trojan_Sailor_5
{
strings:
	$a0 = { 8bec8b5e048beb81ed03002e80be480088745ce80300eb57900e1f1e073efe8648008dbe5904b9e5038db658048a }


condition:
	$a0
}