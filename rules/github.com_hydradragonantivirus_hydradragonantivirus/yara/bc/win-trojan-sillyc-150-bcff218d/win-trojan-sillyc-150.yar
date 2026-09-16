rule Win_Trojan_SillyC_150
{
strings:
	$a0 = { 8b960f0283c203cd21b4408d960301b9100190cd21b4408d9613023e8b8e1102cd21585ab43ecd }


condition:
	$a0
}