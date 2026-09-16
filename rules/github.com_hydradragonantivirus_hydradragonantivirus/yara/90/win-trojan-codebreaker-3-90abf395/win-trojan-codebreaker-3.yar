rule Win_Trojan_CodeBreaker_3
{
strings:
	$a0 = { 6e0152e89affb43fb96e018d967102cd215ae88bffb91d038d960301b440cd21fe864b04b801 }


condition:
	$a0
}