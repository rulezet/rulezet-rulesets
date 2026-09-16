rule Win_Trojan_Doodle_1
{
strings:
	$a0 = { b80135cd218bf38cc7b81c35cd218c06 }


condition:
	$a0
}