rule Win_Trojan_VCG_1
{
strings:
	$a0 = { 5b5351b440bafd00b90300cd21595bb440ba00018cc1cd210e078bf54e2e8a043c00750258 }


condition:
	$a0
}