rule Win_Trojan_Rbrute_2
{
strings:
	$a0 = { 3139383637383631383732393031303437736466 }


condition:
	$a0
}