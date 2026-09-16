rule Win_Trojan_VGEN_754
{
strings:
	$a0 = { bd02b04fbe29028bd92800e2fa389e50c57f8307504fab797db2bebc4fab9390a9a99b94a17d929e9c4f4e906fc2b2 }


condition:
	$a0
}