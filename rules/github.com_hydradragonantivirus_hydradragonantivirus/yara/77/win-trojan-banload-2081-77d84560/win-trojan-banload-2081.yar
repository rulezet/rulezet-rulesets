rule Win_Trojan_Banload_2081
{
strings:
	$a0 = { 6800504800680b104000c3c33002d94ade0aa0dbb0657001 }


condition:
	$a0
}