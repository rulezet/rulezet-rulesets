rule Win_Trojan_Havoc_1
{
strings:
	$a0 = { eb07b54fb10dba0000ba0001b80602cd1372f933c08ec0be007abf007cb90001f3a5fa8cc8 }


condition:
	$a0
}