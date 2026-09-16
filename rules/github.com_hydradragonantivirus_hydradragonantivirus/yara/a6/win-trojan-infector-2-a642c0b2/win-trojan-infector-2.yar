rule Win_Trojan_Infector_2
{
strings:
	$a0 = { d5018b1efc02b440cd21722933c933d28b1efc02b80042 }


condition:
	$a0
}