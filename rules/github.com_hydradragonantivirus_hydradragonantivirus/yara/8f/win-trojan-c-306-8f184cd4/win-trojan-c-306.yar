rule Win_Trojan_C_306
{
strings:
	$a0 = { 5068697275732d436f6e7374727563746f72 }

	$a1 = { 5c00520075006e005c }


condition:
	$a0 and $a1
}