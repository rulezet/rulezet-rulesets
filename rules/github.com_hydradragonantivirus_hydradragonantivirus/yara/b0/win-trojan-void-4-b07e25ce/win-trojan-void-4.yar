rule Win_Trojan_Void_4
{
strings:
	$a0 = { 01be86018bfeb90200f3a7750826c606ed01ffeb5226803eec0100754a33c08ec026c4068400a308088c060a08 }


condition:
	$a0
}