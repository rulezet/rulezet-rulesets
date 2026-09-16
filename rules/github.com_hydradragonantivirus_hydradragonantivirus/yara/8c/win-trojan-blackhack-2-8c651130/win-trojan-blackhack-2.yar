rule Win_Trojan_BlackHack_2
{
strings:
	$a0 = { 760a2e8007074bebf9ff2cb987d1f3c0fffdf932f98507fff9c0ff05f922f9850707f9f4c6fae4f727f015277afd62 }


condition:
	$a0
}