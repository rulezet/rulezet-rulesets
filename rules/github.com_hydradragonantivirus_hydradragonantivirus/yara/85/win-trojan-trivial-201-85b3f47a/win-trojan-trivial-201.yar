rule Win_Trojan_Trivial_201
{
strings:
	$a0 = { 4eba1f00cd217214b43d40ba9e00cd21b74093ba0000b125cd21b44febe32a2e434f4d00 }


condition:
	$a0
}