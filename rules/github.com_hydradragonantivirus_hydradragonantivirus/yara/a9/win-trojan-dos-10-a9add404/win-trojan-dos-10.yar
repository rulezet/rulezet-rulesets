rule Win_Trojan_DOS_10
{
strings:
	$a0 = { 890d8bf54e2e8a048845025b5351b440bafd00b90300cd21595bb440ba00018cc1cd210e07 }


condition:
	$a0
}