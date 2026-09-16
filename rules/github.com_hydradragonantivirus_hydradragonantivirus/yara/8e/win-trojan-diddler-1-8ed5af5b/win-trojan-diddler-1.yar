rule Win_Trojan_Diddler_1
{
strings:
	$a0 = { 3fb903008d96be01cd213e80bebe01e9742f3e8b86 }


condition:
	$a0
}