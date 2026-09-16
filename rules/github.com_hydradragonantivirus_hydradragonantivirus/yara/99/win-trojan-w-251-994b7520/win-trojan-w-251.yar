rule Win_Trojan_W_251
{
strings:
	$a0 = { 81e20000f0ffb80000f7bf81fa0000f0bf740e8bc281fa0000f0770f856e030000 }


condition:
	$a0
}