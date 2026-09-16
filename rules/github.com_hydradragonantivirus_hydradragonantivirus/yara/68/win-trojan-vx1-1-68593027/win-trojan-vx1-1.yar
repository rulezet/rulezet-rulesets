rule Win_Trojan_VX1_1
{
strings:
	$a0 = { ff369001b41aba00fccd21b44eba9d0133c9cd21b8023dba1efccd218bd82e8b }


condition:
	$a0
}