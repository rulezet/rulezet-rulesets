rule Win_Trojan_Astra_1
{
strings:
	$a0 = { 535657fa8cc88ed88ec0be780003f58bfeb98b018bddfcad33876000abe2f85f5e5b071fc3 }


condition:
	$a0
}