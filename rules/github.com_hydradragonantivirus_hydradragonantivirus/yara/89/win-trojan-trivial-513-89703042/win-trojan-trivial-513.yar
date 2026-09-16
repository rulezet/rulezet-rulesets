rule Win_Trojan_Trivial_513
{
strings:
	$a0 = { 33c9ba5f01cd21b8023dba9e00cd2193b440b96500ba0001cd21b43ecd21ba3c01b409cd21cd }


condition:
	$a0
}