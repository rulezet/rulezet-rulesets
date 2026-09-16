rule Win_Trojan_Vienna_26
{
strings:
	$a0 = { d683c60a90bf0001b90300f3a489 }


condition:
	$a0
}