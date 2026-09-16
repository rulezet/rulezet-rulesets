rule Win_Trojan_Xvxh_2
{
strings:
	$a0 = { e9ca01c704e900894c018bd6b90300b440cd2133c933d2b80042cd218bd6b90100b440cd218bfe }


condition:
	$a0
}