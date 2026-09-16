rule Win_Trojan_C_32
{
strings:
	$a0 = { 4a8bdcb104d3eb43cd21bb2c008b07a3de018cc8a3e201a3e601a3ea01bad101bbde01b8004bcd21fa8bd88c }


condition:
	$a0
}