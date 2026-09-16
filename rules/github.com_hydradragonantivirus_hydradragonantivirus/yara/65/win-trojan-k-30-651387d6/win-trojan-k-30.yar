rule Win_Trojan_K_30
{
strings:
	$a0 = { 8b1e0503b80042cd217236ba1001b99903908b1e0503b440cd217225b90000ba00008b1e }


condition:
	$a0
}