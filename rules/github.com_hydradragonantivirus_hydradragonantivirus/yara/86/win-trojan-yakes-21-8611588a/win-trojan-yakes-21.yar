rule Win_Trojan_Yakes_21
{
strings:
	$a0 = { 8b45ac3945dc74508b45e089c181c101000000894de08a108b45d4 }


condition:
	$a0
}