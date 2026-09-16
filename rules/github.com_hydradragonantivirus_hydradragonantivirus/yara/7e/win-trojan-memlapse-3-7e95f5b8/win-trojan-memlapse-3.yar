rule Win_Trojan_MemLapse_3
{
strings:
	$a0 = { 9090b801faba4559cd16e800005d81ed0f018d9e2202ff374343ff37b41a8d962602cd21ccb44e8d961a02cd2172 }


condition:
	$a0
}