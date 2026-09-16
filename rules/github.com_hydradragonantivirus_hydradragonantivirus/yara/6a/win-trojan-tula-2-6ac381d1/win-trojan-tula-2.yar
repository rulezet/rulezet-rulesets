rule Win_Trojan_Tula_2
{
strings:
	$a0 = { 01f0abaf96ab95ab31d2b90406b440cc720ee81700ba1806b91c00b440cc72005a59b80157 }


condition:
	$a0
}