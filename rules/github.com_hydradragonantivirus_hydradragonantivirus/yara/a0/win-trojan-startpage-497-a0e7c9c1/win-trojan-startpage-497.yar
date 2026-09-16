rule Win_Trojan_Startpage_497
{
strings:
	$a0 = { eb1066623a432b2b484f4f4b90e9988048 }

	$a1 = { 6661762e646174 }

	$a2 = { 5469626961436c69656e74 }

	$a3 = { 2e646174004f706973 }


condition:
	$a0 and $a1 and $a2 and $a3
}