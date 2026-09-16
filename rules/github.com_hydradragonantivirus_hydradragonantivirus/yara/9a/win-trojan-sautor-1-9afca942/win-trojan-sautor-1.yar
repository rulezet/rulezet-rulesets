rule Win_Trojan_Sautor_1
{
strings:
	$a0 = { 83bdf0feffff200f8d050100008b8df4feffff234dfc85c90f84de00000068dca042000fbe55f8526874a14200 }


condition:
	$a0
}