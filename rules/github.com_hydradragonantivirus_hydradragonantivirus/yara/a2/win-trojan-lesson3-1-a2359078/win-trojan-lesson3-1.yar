rule Win_Trojan_Lesson3_1
{
strings:
	$a0 = { 9090e80000565e5e81c60901bf0001fca5a581ee1001e81500eb2d90e80f00b440b914018bd6cd21e803 }


condition:
	$a0
}