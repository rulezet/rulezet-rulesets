rule Win_Trojan_Small_4091
{
strings:
	$a0 = { eb02cd2deb3ec3e83d000000e874000000e82000000009c975f7 }


condition:
	$a0
}