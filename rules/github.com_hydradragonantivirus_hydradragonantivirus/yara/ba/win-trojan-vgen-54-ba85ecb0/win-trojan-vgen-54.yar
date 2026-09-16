rule Win_Trojan_VGEN_54
{
strings:
	$a0 = { 30cd213c02730533c00650cbbf04028b3602002bf781fe00107203be0010fa8ed781c45e29fb7310161fe84e0733c0 }


condition:
	$a0
}