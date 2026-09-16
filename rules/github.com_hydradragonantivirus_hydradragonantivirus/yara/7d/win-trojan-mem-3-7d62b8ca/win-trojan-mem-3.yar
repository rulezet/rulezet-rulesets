rule Win_Trojan_mem_3
{
strings:
	$a0 = { 74e880fc4b746080fc11741280fc12740d }


condition:
	$a0
}