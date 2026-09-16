rule Win_Trojan_Horse_7
{
strings:
	$a0 = { 1b00ba6e068bf2cd212e803e5e06 }


condition:
	$a0
}