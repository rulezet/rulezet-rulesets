rule Win_Trojan_Python_5
{
strings:
	$a0 = { 6d796d7478636f64653d676574737472696e67286d29 }


condition:
	$a0
}