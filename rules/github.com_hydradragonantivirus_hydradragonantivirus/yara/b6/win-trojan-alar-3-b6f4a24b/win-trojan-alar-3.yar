rule Win_Trojan_Alar_3
{
strings:
	$a0 = { 9d0f85d8ff82ee0082ec00e90300960408685d02f882eb0026c3 }


condition:
	$a0
}