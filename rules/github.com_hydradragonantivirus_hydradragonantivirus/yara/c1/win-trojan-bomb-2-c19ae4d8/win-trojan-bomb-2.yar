rule Win_Trojan_Bomb_2
{
strings:
	$a0 = { 070038015589e5b80100509a0c005f0183c4025589e5b87a07509a0f007d0183c402b8bc07509a }


condition:
	$a0
}