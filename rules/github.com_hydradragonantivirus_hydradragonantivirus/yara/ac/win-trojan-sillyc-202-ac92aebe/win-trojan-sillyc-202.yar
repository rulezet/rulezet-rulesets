rule Win_Trojan_SillyC_202
{
strings:
	$a0 = { b4018a661bcd215f595a83c71533c08a6624cd21c605e98b441a2d0300894501c64503adb10487 }


condition:
	$a0
}