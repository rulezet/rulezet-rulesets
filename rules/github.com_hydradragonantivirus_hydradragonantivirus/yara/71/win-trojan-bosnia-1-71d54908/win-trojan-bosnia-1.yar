rule Win_Trojan_Bosnia_1
{
strings:
	$a0 = { b9280cf3a4061fb82135cd21891ef8008c06fa00bab201b82125cd21b8db33cd21b42acd21 }


condition:
	$a0
}