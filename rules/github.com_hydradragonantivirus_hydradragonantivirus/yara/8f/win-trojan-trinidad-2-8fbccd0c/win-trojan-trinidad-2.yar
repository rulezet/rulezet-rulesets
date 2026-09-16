rule Win_Trojan_Trinidad_2
{
strings:
	$a0 = { 5fbf0001ffe7[0-10]8db6????bf0001a5a4c3 }


condition:
	$a0
}