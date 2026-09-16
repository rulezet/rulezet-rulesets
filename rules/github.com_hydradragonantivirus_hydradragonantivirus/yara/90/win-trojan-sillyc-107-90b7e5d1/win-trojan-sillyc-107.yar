rule Win_Trojan_SillyC_107
{
strings:
	$a0 = { 3c5356743ac7045356b440b9df008d960001cd218b8601012d03008904b8004233c933d2cd21b4 }


condition:
	$a0
}