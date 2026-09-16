rule Win_Trojan_Y_14
{
strings:
	$a0 = { 4abb4800cd21b84853cd212d5449745a9090b80058cd2150b8015850bb8200cd21b80258cd2153 }


condition:
	$a0
}