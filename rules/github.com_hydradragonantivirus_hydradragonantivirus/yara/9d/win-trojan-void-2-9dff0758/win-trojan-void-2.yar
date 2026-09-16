rule Win_Trojan_Void_2
{
strings:
	$a0 = { 01be86018bfeb90200f3a7750826c606ed01ffeb4c26803eec0100754433c08ec026c4068400a3cb078c06cd07 }


condition:
	$a0
}