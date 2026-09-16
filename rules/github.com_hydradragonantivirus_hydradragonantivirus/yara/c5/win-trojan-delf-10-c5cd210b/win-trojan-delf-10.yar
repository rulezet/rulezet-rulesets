rule Win_Trojan_Delf_10
{
strings:
	$a0 = { 6466676b6f6f6c6972632049524320636f6d706f6e656e7420666f722044656c70686900ffffffff }


condition:
	$a0
}