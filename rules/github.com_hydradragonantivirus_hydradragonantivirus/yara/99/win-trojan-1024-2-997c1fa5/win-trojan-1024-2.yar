rule Win_Trojan_1024_2
{
strings:
	$a0 = { 041f3df0f07505a10301cd0526a1 }


condition:
	$a0
}