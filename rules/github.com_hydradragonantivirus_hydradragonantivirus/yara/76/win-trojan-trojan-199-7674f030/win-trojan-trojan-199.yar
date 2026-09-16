rule Win_Trojan_Trojan_199
{
strings:
	$a0 = { a5070e1f8b166700803e6e000b750f8916 }


condition:
	$a0
}