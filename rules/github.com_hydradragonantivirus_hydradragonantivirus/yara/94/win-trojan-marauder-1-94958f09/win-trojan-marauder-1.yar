rule Win_Trojan_Marauder_1
{
strings:
	$a0 = { 048bfe50535152b98f01fdad33861901abe2f8 }


condition:
	$a0
}