rule Win_Trojan_VGEN_449
{
strings:
	$a0 = { a210015804b8a203015880fd0074060408fecdebf5a20a01e82d003c0277f98ac8b00180f900 }


condition:
	$a0
}