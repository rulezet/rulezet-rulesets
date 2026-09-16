rule Win_Trojan_BadBoy_3
{
strings:
	$a0 = { 016014b803121ecd2f268c1e17011f }


condition:
	$a0
}