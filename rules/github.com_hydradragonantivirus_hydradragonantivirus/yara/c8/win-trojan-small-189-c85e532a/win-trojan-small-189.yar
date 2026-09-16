rule Win_Trojan_Small_189
{
strings:
	$a0 = { 568bfebe4201b5fdf3a448601e80fc4075118bf2803ce9750a0e1fba0001b94200cd211f }


condition:
	$a0
}