rule Win_Trojan_Australian_7
{
strings:
	$a0 = { 40b9d10099cd21b8004233c9cd21b440b118bad100cd21b4 }


condition:
	$a0
}