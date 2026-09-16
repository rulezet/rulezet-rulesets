rule Win_Trojan_Camel_10
{
strings:
	$a0 = { e800005d81ed????b42ccd218adab40bcd2180fc00750703dd2e3a0774??1e06b42c80f466bbffffcd21 }


condition:
	$a0
}