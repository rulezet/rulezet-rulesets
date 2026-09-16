rule Win_Trojan_Primus_3
{
strings:
	$a0 = { 51b440ba0002b9000290cd38e8240059b4408bd6cd38c606220400b80057cd3840cd38b43e }


condition:
	$a0
}