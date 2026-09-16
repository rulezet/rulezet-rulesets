rule Win_Trojan_Waledac_37
{
strings:
	$a0 = { 80cd91c0fb1980efef66d3c381d789e47261f7c79f377fe180ce }


condition:
	$a0
}