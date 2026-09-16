rule Win_Trojan_Small_3956
{
strings:
	$a0 = { 53535353bfb8??4000ff1785c0752d }


condition:
	$a0
}