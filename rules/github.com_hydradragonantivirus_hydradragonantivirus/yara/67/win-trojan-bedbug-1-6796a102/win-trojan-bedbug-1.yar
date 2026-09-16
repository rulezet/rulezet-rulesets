rule Win_Trojan_Bedbug_1
{
strings:
	$a0 = { 40eb02b43fe8150072022bc1c333c933d2b80242eb0733 }


condition:
	$a0
}