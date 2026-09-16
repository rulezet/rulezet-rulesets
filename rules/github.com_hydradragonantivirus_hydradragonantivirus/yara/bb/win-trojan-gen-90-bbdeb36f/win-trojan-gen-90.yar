rule Win_Trojan_Gen_90
{
strings:
	$a0 = { 3fcd2129c85875ddffe0b440ebf3 }


condition:
	$a0
}