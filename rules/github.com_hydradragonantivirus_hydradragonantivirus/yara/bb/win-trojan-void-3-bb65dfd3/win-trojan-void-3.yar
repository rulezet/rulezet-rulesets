rule Win_Trojan_Void_3
{
strings:
	$a0 = { 01be86018bfeb90200f3a7750826c606ed01ffeb4c26803eec0100754433c08ec026c4068400a30b078c060d07 }


condition:
	$a0
}