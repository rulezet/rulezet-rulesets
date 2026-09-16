rule Win_Trojan_Freew_1
{
strings:
	$a0 = { a002b440cd218f065201b801578b0e190181c9ff008b161b01cd21 }


condition:
	$a0
}