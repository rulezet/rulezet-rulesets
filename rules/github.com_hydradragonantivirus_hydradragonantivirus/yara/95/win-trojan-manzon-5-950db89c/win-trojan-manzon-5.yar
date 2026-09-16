rule Win_Trojan_Manzon_5
{
strings:
	$a0 = { 9292905bb4408b0e890383c10cba9808cd21891e9608929290929290bf9e08033e8903c605c3 }


condition:
	$a0
}