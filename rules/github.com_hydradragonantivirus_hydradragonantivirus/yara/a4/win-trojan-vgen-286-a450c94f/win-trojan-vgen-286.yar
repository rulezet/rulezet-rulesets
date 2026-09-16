rule Win_Trojan_VGEN_286
{
strings:
	$a0 = { 1f8b0e0c008bf94f8bf78cdb031e0a008ec3fdf3a453b82b0050cb2e8b2e08008cda89e83d00107603b8001029c5 }


condition:
	$a0
}