rule Win_Trojan_Jel_1
{
strings:
	$a0 = { e80000cc5d83ed0381ed0001ba1b038bca8db62b012e8abe47042e303ce90400b44ccd21b40dcd21 }


condition:
	$a0
}