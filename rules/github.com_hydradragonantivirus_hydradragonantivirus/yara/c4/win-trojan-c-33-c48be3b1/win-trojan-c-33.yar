rule Win_Trojan_C_33
{
strings:
	$a0 = { 03b44a8bdcb104d3eb43cd21bb2c008b07a3fe018cc8a30202a30602a30a02baf101bbfe01b8004bcd21fa8bd8 }


condition:
	$a0
}