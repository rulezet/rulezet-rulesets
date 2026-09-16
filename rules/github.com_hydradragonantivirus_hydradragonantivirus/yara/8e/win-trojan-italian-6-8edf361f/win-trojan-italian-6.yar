rule Win_Trojan_Italian_6
{
strings:
	$a0 = { 9e1601b918032e8ab646042e8a2732e62e882743e2f5c3 }


condition:
	$a0
}