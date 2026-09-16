rule Win_Trojan_Trivial_490
{
strings:
	$a0 = { 3cba7b01b90000cd218bd8b98800ba0001b440cd2161b44eba5f01cd21b8013dba9e00cd218bd8ba0001b440b98800cd21b44fcd2173e6b409ba6501cd21cd20 }


condition:
	$a0
}