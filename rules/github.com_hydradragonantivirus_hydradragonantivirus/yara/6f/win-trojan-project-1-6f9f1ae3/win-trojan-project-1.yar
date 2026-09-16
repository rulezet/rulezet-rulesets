rule Win_Trojan_Project_1
{
strings:
	$a0 = { 96060459cd21b8024233c999cd21b440b921038d960501cd21b801573e8b96f4033e8b8ef2 }


condition:
	$a0
}