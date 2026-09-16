rule Win_Trojan_Small_4438
{
strings:
	$a0 = { 6a00810424??3042008d1c240f6e230f7e }


condition:
	$a0
}