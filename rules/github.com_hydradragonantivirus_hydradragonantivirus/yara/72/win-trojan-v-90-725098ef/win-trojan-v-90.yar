rule Win_Trojan_V_90
{
strings:
	$a0 = { 0306060e1fb1ffb4ffcd2183f9007503eb5790bd40001fa102002bc5a3020097578cd848501f292e030033c951 }


condition:
	$a0
}