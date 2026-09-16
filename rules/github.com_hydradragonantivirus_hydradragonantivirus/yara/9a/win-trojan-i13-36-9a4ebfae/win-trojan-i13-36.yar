rule Win_Trojan_I13_36
{
strings:
	$a0 = { 33d2b9d701cd21e81900b440b90400ba3701cd21b43e }


condition:
	$a0
}