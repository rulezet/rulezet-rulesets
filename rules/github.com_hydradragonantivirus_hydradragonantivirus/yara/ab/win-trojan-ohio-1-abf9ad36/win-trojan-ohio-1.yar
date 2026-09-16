rule Win_Trojan_Ohio_1
{
strings:
	$a0 = { d3e08ec0be007c33ffb90410fcf3a406b8000450 }


condition:
	$a0
}