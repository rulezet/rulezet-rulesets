rule Win_Spyware_ye_203
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]c816d227e382356709b6d9c3e38030 }


condition:
	$a0
}