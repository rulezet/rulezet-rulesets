rule Win_Trojan_Hates_2
{
strings:
	$a0 = { 2180fa0a7208ba8000b41acd21c3b80011bb000eb9 }


condition:
	$a0
}