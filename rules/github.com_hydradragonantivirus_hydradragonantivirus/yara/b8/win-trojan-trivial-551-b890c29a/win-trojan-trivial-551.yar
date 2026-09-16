rule Win_Trojan_Trivial_551
{
strings:
	$a0 = { b92500be????8bfeac3206????aae2f8c3 }


condition:
	$a0
}