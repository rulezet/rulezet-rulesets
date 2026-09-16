rule Win_Trojan_Crash_1
{
strings:
	$a0 = { c02e03441a051000502eff7418cb061e8cd8488ec0 }


condition:
	$a0
}