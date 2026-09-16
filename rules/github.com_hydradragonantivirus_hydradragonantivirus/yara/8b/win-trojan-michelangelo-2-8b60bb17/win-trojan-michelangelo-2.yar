rule Win_Trojan_Michelangelo_2
{
strings:
	$a0 = { a3157ca14e00a3177c832e130402b106a11304d3e0a31b7c8ec0b81d01a34c008c064e00b9 }


condition:
	$a0
}