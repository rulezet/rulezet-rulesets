rule Win_Trojan_Meditation_4
{
strings:
	$a0 = { 0e580500105007be0001fe060401b92b012bfff3a4b44e }


condition:
	$a0
}