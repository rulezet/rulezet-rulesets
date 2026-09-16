rule Win_Trojan_IRC_22
{
strings:
	$a0 = { 494e5649444941aec1a17742 }

	$a1 = { 41844e534849454c4400 }

	$a2 = { 73094ce2 }

	$a3 = { b37c8b471039464c }


condition:
	$a0 and $a1 and $a2 and $a3
}