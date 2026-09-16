rule Win_Trojan_Small_4401
{
strings:
	$a0 = { 56e9[0-255]81e8891a25260589362726535e01c6c3 }


condition:
	$a0
}