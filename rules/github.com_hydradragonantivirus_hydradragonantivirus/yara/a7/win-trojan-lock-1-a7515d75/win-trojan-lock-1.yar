rule Win_Trojan_Lock_1
{
strings:
	$a0 = { 40b90100ba1305e8c3feb440b90200ba2d05e8b8feb440b90200ba1405e8adfec30e1fb80242e8 }


condition:
	$a0
}