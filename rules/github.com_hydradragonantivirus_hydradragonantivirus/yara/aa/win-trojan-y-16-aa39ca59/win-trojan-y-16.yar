rule Win_Trojan_Y_16
{
strings:
	$a0 = { 4abb5e00cd21b84853cd212d5449746e9090b80058cd2150b8015850bb8200cd21b80258cd2153 }


condition:
	$a0
}