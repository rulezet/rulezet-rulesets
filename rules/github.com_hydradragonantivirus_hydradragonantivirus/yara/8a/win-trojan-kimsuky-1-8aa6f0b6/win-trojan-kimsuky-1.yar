rule Win_Trojan_Kimsuky_1
{
strings:
	$a0 = { 75726c686173683d2672656d656d6265726d653d }

	$a1 = { 2672656164726573706f6e7365 }


condition:
	$a0 and $a1
}