rule Win_Trojan_Small_4457
{
strings:
	$a0 = { 8d0544858503683255430350e84600000050 }


condition:
	$a0
}