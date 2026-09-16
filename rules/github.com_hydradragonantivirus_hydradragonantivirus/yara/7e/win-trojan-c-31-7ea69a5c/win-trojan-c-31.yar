rule Win_Trojan_C_31
{
strings:
	$a0 = { 4a8bdcb104d3eb43cd21bb2c008b07a3ad018cc8a3b101a3b501a3b901baa001bbad01b8004bcd21fa8bd88c }


condition:
	$a0
}