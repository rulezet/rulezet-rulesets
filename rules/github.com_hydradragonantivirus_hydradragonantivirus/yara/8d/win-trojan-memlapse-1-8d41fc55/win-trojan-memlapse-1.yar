rule Win_Trojan_MemLapse_1
{
strings:
	$a0 = { 9090b801faba4559cd16e800008bf4bf2f02a58b2e2f02444481ed0f018d9e2502ff3783c302ff37b41a8d962902 }


condition:
	$a0
}