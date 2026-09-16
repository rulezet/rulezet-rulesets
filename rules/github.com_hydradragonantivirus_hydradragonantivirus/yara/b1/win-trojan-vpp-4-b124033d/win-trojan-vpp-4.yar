rule Win_Trojan_Vpp_4
{
strings:
	$a0 = { d301c604e889440187f2b440b90300cd21b802422bd28bcacd218bf581c6db0203f78bfd81c7 }


condition:
	$a0
}