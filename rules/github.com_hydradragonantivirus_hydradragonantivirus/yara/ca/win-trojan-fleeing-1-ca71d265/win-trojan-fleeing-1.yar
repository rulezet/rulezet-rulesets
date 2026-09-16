rule Win_Trojan_Fleeing_1
{
strings:
	$a0 = { 22140035ecfde496ff13abff9d81dee1dc67fb6a23e09832dee1b49203abffe4fde53d69b1abffe4fdc94c }


condition:
	$a0
}