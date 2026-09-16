rule Win_Trojan_Suicidal_5
{
strings:
	$a0 = { c684d100e98b94f40083ea038994d200c684d40010b440b9 }


condition:
	$a0
}