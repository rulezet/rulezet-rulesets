rule Win_Trojan_VGEN_55
{
strings:
	$a0 = { 30cd213c02730533c00650cbbf08028b3602002bf781fe00107203be0010fa8ed781c44e0efb7310161fe84e0733c0 }


condition:
	$a0
}