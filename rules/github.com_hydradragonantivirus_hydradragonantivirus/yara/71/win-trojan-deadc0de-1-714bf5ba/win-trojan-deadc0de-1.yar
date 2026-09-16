rule Win_Trojan_Deadc0de_1
{
strings:
	$a0 = { dec0adde }


condition:
	$a0
}