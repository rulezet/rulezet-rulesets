rule Win_Trojan_Satan_1
{
strings:
	$a0 = { c20402cd21b90000b802428bd1cd212d03008bf581 }


condition:
	$a0
}