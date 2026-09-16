rule Win_Trojan_Byaka_1
{
strings:
	$a0 = { 040f04c6060c0400900e33c08ec0bb490426803f037e03e9d600fcb800bb8ec0be00018bfeb96003f3a4ff2e3b }


condition:
	$a0
}