rule Win_Trojan_DarkElf_3
{
strings:
	$a0 = { 01500e1fb9ce008b8494082bc33020d0c4d0c402e0fec0d0c843e2f189849408e96cf7 }


condition:
	$a0
}