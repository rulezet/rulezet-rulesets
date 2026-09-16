rule Win_Trojan_Rajaat_2
{
strings:
	$a0 = { 1530cd2181fb1530741db82135cd21891e98018c069a01b82125ba9c01cd21 }


condition:
	$a0
}