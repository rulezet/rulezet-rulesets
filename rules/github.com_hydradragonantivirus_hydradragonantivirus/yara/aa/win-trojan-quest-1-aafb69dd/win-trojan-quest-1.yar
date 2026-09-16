rule Win_Trojan_Quest_1
{
strings:
	$a0 = { b91900a4e2fdba8402ffd2c353ba7102ffd25bb440b98401ba0001cd2153ba7102ffd25bc3 }


condition:
	$a0
}