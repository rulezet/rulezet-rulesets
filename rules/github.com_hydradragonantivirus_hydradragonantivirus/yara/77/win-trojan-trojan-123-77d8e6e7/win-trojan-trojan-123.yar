rule Win_Trojan_Trojan_123
{
strings:
	$a0 = { 908ed833d2b440cd215bb43ecd215a1f07595b5e5f58 }


condition:
	$a0
}