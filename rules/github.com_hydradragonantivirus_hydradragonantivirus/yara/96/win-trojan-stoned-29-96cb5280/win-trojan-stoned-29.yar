rule Win_Trojan_Stoned_29
{
strings:
	$a0 = { 568ed8bb4c00ba8000c43f897c278c4429a1130448a31304 }


condition:
	$a0
}