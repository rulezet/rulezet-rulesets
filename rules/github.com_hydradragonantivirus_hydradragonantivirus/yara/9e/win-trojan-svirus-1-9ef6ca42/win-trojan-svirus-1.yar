rule Win_Trojan_Svirus_1
{
strings:
	$a0 = { 02b90600b440cd215a5283c206b93c01b440cd215e568b8ca60280e1e080c91f8b94a802b8 }


condition:
	$a0
}