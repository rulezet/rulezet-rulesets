rule Win_Trojan_Meditation_2
{
strings:
	$a0 = { 2e434f4d000000ff570000500e580500105007be0001fe060401b92b012bfff3a4b4 }


condition:
	$a0
}