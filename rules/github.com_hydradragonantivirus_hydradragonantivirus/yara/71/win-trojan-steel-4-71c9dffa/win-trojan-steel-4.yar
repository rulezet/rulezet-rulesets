rule Win_Trojan_Steel_4
{
strings:
	$a0 = { 80fcfe73c6e874ffb8004233c9ba0100cd21b4408d941602b90200cd21b43ecd21ffe52a2e43 }


condition:
	$a0
}