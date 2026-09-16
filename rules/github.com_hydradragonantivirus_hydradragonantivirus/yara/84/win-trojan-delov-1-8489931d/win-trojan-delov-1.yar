rule Win_Trojan_Delov_1
{
strings:
	$a0 = { ac83f83a7404aa41ebf6aa83ee02bf42274000ac83f82e7403aaebf7aabe42274000e835010000e83901000046 }


condition:
	$a0
}