rule Win_Trojan_Kellie_1
{
strings:
	$a0 = { e800005f81ef??008befb41a8d960000cd21ba0100b947018d862400e8 }


condition:
	$a0
}