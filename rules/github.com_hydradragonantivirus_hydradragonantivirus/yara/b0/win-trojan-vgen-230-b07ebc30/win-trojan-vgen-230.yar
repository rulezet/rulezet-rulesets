rule Win_Trojan_VGEN_230
{
strings:
	$a0 = { 5053552ec70604010000b80fffcd213d010175370633c08ec0bb4e00268b078ec0bd001026817e00 }


condition:
	$a0
}