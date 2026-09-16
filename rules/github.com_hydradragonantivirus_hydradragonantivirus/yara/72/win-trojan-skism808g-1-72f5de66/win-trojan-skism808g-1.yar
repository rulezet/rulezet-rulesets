rule Win_Trojan_Skism808G_1
{
strings:
	$a0 = { 51bb38018a2f322e0301882f4381fb60047ef159c3 }


condition:
	$a0
}