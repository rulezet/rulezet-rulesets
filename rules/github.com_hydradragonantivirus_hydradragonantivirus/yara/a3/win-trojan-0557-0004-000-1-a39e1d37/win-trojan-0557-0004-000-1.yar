rule Win_Trojan__0557_0004_000_1
{
strings:
	$a0 = { 02578db63201b96a0151e8adfeb440595acd21b80157595acd21b801431f5a59cd21b43ecd215d }


condition:
	$a0
}