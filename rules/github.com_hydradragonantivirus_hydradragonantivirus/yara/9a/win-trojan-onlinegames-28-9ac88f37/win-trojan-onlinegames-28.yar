rule Win_Trojan_Onlinegames_28
{
strings:
	$a0 = { 68cb5d4300e8a847020068d3604300e8e4 }

	$a1 = { 10736961526663784565665308 }


condition:
	$a0 and $a1
}