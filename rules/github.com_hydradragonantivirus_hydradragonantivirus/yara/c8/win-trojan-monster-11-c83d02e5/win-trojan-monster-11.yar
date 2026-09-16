rule Win_Trojan_Monster_11
{
strings:
	$a0 = { 1ca53938a7d21c1ecbd03c4ba95a2fcf9cdbf91cd03c43f65be3590fa907a7391f1ecbd03c9d610f }


condition:
	$a0
}