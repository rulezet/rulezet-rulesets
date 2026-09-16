rule Win_Trojan_NoHook_4
{
strings:
	$a0 = { 02b95100f3a4c51e0a00c647ff85cd200018020000b8013dcd21930e1fb440b9 }


condition:
	$a0
}