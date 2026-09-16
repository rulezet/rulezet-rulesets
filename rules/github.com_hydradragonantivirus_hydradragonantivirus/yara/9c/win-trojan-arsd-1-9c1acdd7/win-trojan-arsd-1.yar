rule Win_Trojan_Arsd_1
{
strings:
	$a0 = { 14ff56b936dc5abd1b93ebea5f21b835731bfca6dc6f01248b1485b86c280d3bd1740940b3bb954a1a741572e51a890c8b00cfb7904924fe81c3228da5687ab4 }


condition:
	$a0
}