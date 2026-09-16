rule Win_Trojan_Wormsign_2
{
strings:
	$a0 = { 24576f726d7369676e20210a0d242a2e636f6d00 }


condition:
	$a0
}