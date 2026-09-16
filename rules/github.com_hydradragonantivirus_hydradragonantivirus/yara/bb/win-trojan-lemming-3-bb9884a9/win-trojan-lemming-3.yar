rule Win_Trojan_Lemming_3
{
strings:
	$a0 = { 2fe909e96204ecf7ea8302e929ffec4654b92113ce30b91713278b1ece305c84c81227c746f20384 }


condition:
	$a0
}