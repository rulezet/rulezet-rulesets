rule Win_Trojan_Mono_5
{
strings:
	$a0 = { 90909090909090909090909090909090908bff8bff8bff8bff8bff8bc08bdb8bc98bf68bff8bed90908bd28bc08bdb8bc98bf68bff8bed908bd28bc08bd2908bc08bdb8bc9908bf68bff8bed }


condition:
	$a0
}