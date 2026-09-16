rule Win_Trojan_Nax_2
{
strings:
	$a0 = { 5c8e7dabfd43e803d75d4241e6745dfa5f439162e5075ffc3b40e2565cbfafe742709ccd84e23047 }


condition:
	$a0
}