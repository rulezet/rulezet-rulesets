rule Win_Trojan_I13_11
{
strings:
	$a0 = { b985008d96c001cd21b43ecd218db68102bf000157fca5a533c033db33c933d233f633ff33ed }


condition:
	$a0
}