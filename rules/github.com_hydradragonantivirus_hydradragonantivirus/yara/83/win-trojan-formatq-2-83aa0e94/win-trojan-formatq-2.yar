rule Win_Trojan_Formatq_2
{
strings:
	$a0 = { 573a3b583a3b593a3b5a3a2920646f20666f726d617420252561202f71202f78202f79 }


condition:
	$a0
}