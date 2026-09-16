rule Win_Trojan_TSC_1
{
strings:
	$a0 = { 05009090909090e800005e81ee0c0156ba8a0303f28cd88ec0bf0001b90400f3a45e06b42fcd21899c92038c8494 }


condition:
	$a0
}