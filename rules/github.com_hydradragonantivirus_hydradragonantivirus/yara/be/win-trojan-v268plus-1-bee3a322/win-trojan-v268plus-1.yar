rule Win_Trojan_V268plus_1
{
strings:
	$a0 = { 8cc980c5108ec10650be00015631 }


condition:
	$a0
}