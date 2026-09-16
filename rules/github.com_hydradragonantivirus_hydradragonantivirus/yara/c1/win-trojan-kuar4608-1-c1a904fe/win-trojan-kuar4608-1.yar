rule Win_Trojan_KUAR4608_1
{
strings:
	$a0 = { 7cfbfc161fcd122d0b00a31304b106d3e08ec0be007c33ffb90001f3a5b80802bb000226803e }


condition:
	$a0
}