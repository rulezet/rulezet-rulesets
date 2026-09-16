rule Win_Trojan_StahlplatteG_1
{
strings:
	$a0 = { 90900e58bb007f39d87203e947018ec3be0000bf0008 }


condition:
	$a0
}