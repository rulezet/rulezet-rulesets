rule Win_Trojan_Darklord_1
{
strings:
	$a0 = { 59eccd213be8753e0e1f582e8e069d }


condition:
	$a0
}