rule Win_Trojan_Small_1091
{
strings:
	$a0 = { ffff3bf374cc8b45fc6aff8945f8538d45f4506a028975f4ff152820400085c0755856ff150c204000eba76a445e568d45a05350e8 }


condition:
	$a0
}