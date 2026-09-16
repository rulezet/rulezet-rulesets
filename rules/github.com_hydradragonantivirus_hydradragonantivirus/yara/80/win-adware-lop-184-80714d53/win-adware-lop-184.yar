rule Win_Adware_Lop_184
{
strings:
	$a0 = { cf5a8d12be61c468ea83f038ce522b1985aeed9d8eae90af4955b9685e078718e94071433e8fa19811887ee2b8fdebbee568cccac8e46629b8a12f84 }


condition:
	$a0
}