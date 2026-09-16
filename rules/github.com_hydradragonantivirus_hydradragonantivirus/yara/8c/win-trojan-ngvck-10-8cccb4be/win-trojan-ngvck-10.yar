rule Win_Trojan_NGVCK_10
{
strings:
	$a0 = { e8000000005a81ea89a940002bed03ea8bfd85ff7420685d0300008bcd81c1baa940005a8b19c1c31489 }


condition:
	$a0
}