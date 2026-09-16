rule Win_Trojan_Gotcha_10
{
strings:
	$a0 = { f0bf0001b90800f3a4b8000150b8dadacd2180fca57403 }


condition:
	$a0
}