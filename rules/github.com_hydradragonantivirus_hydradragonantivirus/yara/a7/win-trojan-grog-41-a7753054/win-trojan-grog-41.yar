rule Win_Trojan_Grog_41
{
strings:
	$a0 = { 3dcd21723f9353b82012cd2fb81612268a1dcd2f26c6 }


condition:
	$a0
}