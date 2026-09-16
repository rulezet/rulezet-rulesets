rule Win_Trojan_RP_1
{
strings:
	$a0 = { 01fcf3a5cd1980fc02756183f901755c80fe0075572ec6063f7c009c2eff1e407c72742681bf }


condition:
	$a0
}