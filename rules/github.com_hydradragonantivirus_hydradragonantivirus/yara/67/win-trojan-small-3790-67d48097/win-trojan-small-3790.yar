rule Win_Trojan_Small_3790
{
strings:
	$a0 = { 659ab54e4fd0e90dafa4ffd7129dfb99cb6ab0934ebbc799c36ab49955d1f0464bcc6d8364816c866097fbf65e46a40ed24c9c68a8d3eb123a49d7ceaea4679a936aac64dabac816a6d31c0b8306 }


condition:
	$a0
}