rule Win_Trojan_VGEN_492
{
strings:
	$a0 = { 813e0000cd207503e9a8012bc0fa8ed0bc007cfbfc161fcd122d0b00a31304b106d3e08ec0be007c }


condition:
	$a0
}