rule Win_Trojan_VGEN_353
{
strings:
	$a0 = { 30cd213c02730533c00650cbbf6b098b3602002bf781fe00107203be0010fa8ed781c49e1bfb7312161f0ee8570233 }


condition:
	$a0
}