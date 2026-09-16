rule Win_Trojan_IR_1
{
strings:
	$a0 = { 4d75693e81be3b0149527462b8024233c933d2cd }


condition:
	$a0
}