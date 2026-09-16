rule Win_Trojan_C_34
{
strings:
	$a0 = { f900bc2303b44a8bdcb104d3eb43cd21bb2c008b07a3ed018cc8a3f101a3f501a3f901badf01bbed01b8004bcd21 }


condition:
	$a0
}