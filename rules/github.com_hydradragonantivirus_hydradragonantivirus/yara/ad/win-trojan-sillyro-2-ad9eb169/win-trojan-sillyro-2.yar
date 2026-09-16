rule Win_Trojan_SillyRO_2
{
strings:
	$a0 = { cd21891e2e018c063001b425ba1701cd2192cd2780fc4b751168013d58cd21930e1fb440b9 }


condition:
	$a0
}