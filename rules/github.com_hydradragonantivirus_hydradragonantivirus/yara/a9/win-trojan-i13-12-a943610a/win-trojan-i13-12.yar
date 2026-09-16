rule Win_Trojan_I13_12
{
strings:
	$a0 = { 35cd2181fb90017422891ea5018c06a701b82125ba9001cd212ea12c008ec0b449cd21b80031ba0010cd210e07be }


condition:
	$a0
}