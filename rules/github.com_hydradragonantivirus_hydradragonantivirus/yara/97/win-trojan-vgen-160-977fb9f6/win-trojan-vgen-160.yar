rule Win_Trojan_VGEN_160
{
strings:
	$a0 = { 05cd21fcbe40f0b9980251ac3c007502e2f983f900740a5981fe70f572ece919005981ee40f029ce33c98b963a01 }


condition:
	$a0
}