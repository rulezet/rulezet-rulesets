rule Win_Trojan_F_5
{
strings:
	$a0 = { 740b9d2eff2e1200b807009dcfe9acfdb42acd2180fe0b7506be5644e9cafc33f6e9c5fc }


condition:
	$a0
}