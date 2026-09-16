rule Win_Trojan_Khizhnjak_3
{
strings:
	$a0 = { 2172e1ba10018b0ef301b440cd2172d433c933d2b000b442cd2172c8bab803b90300b440cd21eb }


condition:
	$a0
}