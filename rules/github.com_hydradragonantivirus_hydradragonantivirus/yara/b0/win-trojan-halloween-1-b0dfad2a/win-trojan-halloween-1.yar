rule Win_Trojan_Halloween_1
{
strings:
	$a0 = { 7765656e5589e5b8b8009a4402570181ecb8008d7efe16 }


condition:
	$a0
}