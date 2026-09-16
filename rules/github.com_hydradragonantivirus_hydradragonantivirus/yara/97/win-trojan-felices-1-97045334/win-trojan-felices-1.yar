rule Win_Trojan_Felices_1
{
strings:
	$a0 = { 0e1fcd21b42acd2181fa11027515b409ba0501cd21ba8000b90100bb0001b80103cd132e80 }


condition:
	$a0
}