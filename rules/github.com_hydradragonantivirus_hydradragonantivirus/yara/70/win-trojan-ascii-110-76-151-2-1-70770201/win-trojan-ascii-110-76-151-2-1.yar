rule Win_Trojan_Ascii_110_76_151_2_1
{
strings:
	$a0 = { 3131302e37362e3135312e32 }


condition:
	$a0
}