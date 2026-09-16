rule Win_Trojan_Hare_1
{
strings:
	$a0 = { d3e0488ec026813e080053437408b452cd21268b47fe8ec026803e00005a740b }


condition:
	$a0
}