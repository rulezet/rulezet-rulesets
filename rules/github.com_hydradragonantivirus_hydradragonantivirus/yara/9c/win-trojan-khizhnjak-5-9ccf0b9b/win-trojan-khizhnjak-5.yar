rule Win_Trojan_Khizhnjak_5
{
strings:
	$a0 = { 40cd21722933c933d28b1e170432c0b442cd2172198d161904b903008b1e1704b440cd2172088d }


condition:
	$a0
}