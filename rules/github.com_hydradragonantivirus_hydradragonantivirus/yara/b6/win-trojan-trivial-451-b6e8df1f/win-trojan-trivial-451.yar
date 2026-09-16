rule Win_Trojan_Trivial_451
{
strings:
	$a0 = { 3dba1d01cd218bd8b440b92500ba0001cd21b43ecd21b8004ccd21 }


condition:
	$a0
}