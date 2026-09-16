rule Win_Trojan_Small_145
{
strings:
	$a0 = { 7422b8024233c999cd212bc6a30a00b440b180cd21b8004233c9cd21b208b104b440cd21b4 }


condition:
	$a0
}