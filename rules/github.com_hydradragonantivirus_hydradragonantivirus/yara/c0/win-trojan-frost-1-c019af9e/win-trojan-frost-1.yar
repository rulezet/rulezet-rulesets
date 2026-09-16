rule Win_Trojan_Frost_1
{
strings:
	$a0 = { 65722121211d8ceb20a2e1a520a6a8a2f1ac20a220a5a4a8adaeac20aca8e0a5203b28299f }


condition:
	$a0
}