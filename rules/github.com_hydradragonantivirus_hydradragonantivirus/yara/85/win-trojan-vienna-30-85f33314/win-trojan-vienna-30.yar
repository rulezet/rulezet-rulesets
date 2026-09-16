rule Win_Trojan_Vienna_30
{
strings:
	$a0 = { f283c60090bf0001b90300f3a48bf2b430cd213c0075 }


condition:
	$a0
}