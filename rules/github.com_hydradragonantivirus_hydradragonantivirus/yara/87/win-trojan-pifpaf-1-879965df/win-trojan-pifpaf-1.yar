rule Win_Trojan_PifPaf_1
{
strings:
	$a0 = { fcf3a45e0633ff8edfc41e8400c7068400b8005f89 }


condition:
	$a0
}