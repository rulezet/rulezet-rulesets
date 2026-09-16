rule Win_Trojan_Macro_9
{
strings:
	$a0 = { ff980270ff980250fe980240fe980230fed6050800f406120070fea0fe00ff40ff50ff70ff }


condition:
	$a0
}