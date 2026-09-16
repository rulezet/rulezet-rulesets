rule Win_Trojan_MyhWelcome_1
{
strings:
	$a0 = { 16a1025bb91a0051b99902b440ba0000cd21b8004233c999cd21ba9d02b44059cd21b801575a59 }


condition:
	$a0
}