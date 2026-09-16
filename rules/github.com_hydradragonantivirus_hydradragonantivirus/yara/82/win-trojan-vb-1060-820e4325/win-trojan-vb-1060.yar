rule Win_Trojan_VB_1060
{
strings:
	$a0 = { 83ec28f521f6e830010000035c2418f7d6116c243c8d64241cb300e95001000089f689f68d }


condition:
	$a0
}