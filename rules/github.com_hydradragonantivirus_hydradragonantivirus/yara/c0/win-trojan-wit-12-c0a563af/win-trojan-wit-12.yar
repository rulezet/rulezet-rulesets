rule Win_Trojan_Wit_12
{
strings:
	$a0 = { 0473088cc0488ec083c310268b77 }


condition:
	$a0
}