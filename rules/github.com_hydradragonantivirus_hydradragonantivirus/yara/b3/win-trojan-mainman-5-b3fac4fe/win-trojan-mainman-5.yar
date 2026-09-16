rule Win_Trojan_Mainman_5
{
strings:
	$a0 = { 018ae68d960301cd21b43ecd21b43b8d961502cd }


condition:
	$a0
}