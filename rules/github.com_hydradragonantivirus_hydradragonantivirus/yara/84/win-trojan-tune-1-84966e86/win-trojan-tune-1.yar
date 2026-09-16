rule Win_Trojan_Tune_1
{
strings:
	$a0 = { 030050b8004233d28bcacd2158e885ff8bf289440150c604e9b90300b440cd21b468cd21585005 }


condition:
	$a0
}