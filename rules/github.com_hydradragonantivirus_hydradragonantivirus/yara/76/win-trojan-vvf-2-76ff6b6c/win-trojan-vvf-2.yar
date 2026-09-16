rule Win_Trojan_VVF_2
{
strings:
	$a0 = { 02b80125cd21fa9c0e8d06c701509c580d00015006 }


condition:
	$a0
}