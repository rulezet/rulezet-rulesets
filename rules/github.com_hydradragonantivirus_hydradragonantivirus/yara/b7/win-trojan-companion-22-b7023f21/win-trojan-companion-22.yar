rule Win_Trojan_Companion_22
{
strings:
	$a0 = { 0d01cd21ba4801cd273d004b7531508bfab02ef2ae57b84558abaa5f5850529c0ee81b00b8434fabb04daa5a }


condition:
	$a0
}