rule Win_Trojan_Small_4584
{
strings:
	$a0 = { 53bf6e1014138bf78bcff7d981c1324e1413ad8bf733c343663d536f75 }


condition:
	$a0
}