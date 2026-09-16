rule Win_Trojan_M_Five_1
{
strings:
	$a0 = { 6400723d2d0300a33b03b440b94c0333d2cd21bd0100722933ed33c933d2b80042cd21813e5603 }


condition:
	$a0
}