rule Win_Trojan_Trivial_479
{
strings:
	$a0 = { b4952bc981ea6e1080ec47cd21fcb825f7ba27b94d2d23ba81ea89b8f9cd21f5bac6e3b94e00f953584681eac6 }


condition:
	$a0
}