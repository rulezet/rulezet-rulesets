rule Win_Trojan_Willow_1
{
strings:
	$a0 = { fd72045b595dc3baffffb8ffffebf4558bec1e5657 }


condition:
	$a0
}