rule Win_Trojan_B_27
{
strings:
	$a0 = { 1304be007cfa8ed78be68edfa122003d00f07525a3047ca12000a3027c8b07a30a7c488907 }


condition:
	$a0
}