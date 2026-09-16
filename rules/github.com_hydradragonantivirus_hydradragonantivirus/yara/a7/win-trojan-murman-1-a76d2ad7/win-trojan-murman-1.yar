rule Win_Trojan_Murman_1
{
strings:
	$a0 = { b80057e8f3ffc3e8f6ff83c903b80157e8e6ffc3b002e8ccffb440b91c060e1fba00012ec706c0 }


condition:
	$a0
}