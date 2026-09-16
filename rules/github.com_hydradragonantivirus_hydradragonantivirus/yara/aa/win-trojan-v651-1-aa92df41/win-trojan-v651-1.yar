rule Win_Trojan_V651_1
{
strings:
	$a0 = { 2172f52bc875f18bd1b80042cd2172e8a1a002 }


condition:
	$a0
}