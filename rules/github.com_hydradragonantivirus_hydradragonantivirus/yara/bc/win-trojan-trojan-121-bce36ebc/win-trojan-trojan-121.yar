rule Win_Trojan_Trojan_121
{
strings:
	$a0 = { bb1304813f7602744ec7077602b81e00 }


condition:
	$a0
}