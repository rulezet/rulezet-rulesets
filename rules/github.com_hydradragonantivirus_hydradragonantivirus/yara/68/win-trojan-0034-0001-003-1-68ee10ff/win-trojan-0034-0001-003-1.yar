rule Win_Trojan__0034_0001_003_1
{
strings:
	$a0 = { 45118be8b904002bc1a3160ab440ba140acd2126896d1506570e07be0001bf040db98b04f3a5b8 }


condition:
	$a0
}