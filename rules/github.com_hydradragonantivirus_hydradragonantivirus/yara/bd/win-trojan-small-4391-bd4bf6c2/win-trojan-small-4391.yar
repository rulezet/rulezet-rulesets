rule Win_Trojan_Small_4391
{
strings:
	$a0 = { e800000000[0-38]000000[0-7]6800000000[0-10]05??0000[0-37]00100000[0-14]81c?c0(e2|cd)0000[0-58]0f82??ffffff }


condition:
	$a0
}