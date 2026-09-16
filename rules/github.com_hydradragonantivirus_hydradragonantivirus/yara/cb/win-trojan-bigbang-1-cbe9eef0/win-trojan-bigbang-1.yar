rule Win_Trojan_BigBang_1
{
strings:
	$a0 = { 8d960301b440cd21b800422bc999cd21b903008d96 }


condition:
	$a0
}