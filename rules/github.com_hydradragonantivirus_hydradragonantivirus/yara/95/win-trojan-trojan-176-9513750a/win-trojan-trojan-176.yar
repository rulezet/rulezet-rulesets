rule Win_Trojan_Trojan_176
{
strings:
	$a0 = { c0b801028bdc2e803e047d0074462ec606047d0090 }


condition:
	$a0
}