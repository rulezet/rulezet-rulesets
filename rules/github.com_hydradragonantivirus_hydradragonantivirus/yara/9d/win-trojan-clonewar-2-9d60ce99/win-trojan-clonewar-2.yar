rule Win_Trojan_CloneWar_2
{
strings:
	$a0 = { 8bd8b9a303ba????b440cd21b43ecd21ba1a00b90300b80143cd21c3b42ccd218ac5983d10007d }


condition:
	$a0
}