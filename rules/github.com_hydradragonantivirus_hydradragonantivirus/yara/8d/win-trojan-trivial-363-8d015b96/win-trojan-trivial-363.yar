rule Win_Trojan_Trivial_363
{
strings:
	$a0 = { cd2193b43fba5101905459cd21055100905033c9f7e1b442cd2159b4405a52cd21b44febd02a }


condition:
	$a0
}