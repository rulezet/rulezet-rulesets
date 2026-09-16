rule Win_Trojan_Banker_6391
{
strings:
	$a0 = { 5c7472696f7261335c6d6f6e6f747970655c72656c6963742e66696e }


condition:
	$a0
}