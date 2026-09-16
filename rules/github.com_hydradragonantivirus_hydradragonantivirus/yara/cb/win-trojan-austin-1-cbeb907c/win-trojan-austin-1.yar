rule Win_Trojan_Austin_1
{
strings:
	$a0 = { 01b440b949058d960001cd21b8004233c999cd21b440 }


condition:
	$a0
}