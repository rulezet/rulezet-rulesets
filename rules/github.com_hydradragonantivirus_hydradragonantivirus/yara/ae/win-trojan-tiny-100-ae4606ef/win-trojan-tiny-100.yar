rule Win_Trojan_Tiny_100
{
strings:
	$a0 = { 5fbe????4f4f4f5703f7a5a4d1e78ec3a674[0-3]4e4fb1 }


condition:
	$a0
}