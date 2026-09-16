rule Win_Trojan_Doom_5
{
strings:
	$a0 = { 3e0a014574052e033e03012e300547 }


condition:
	$a0
}