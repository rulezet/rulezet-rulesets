rule Win_Trojan_Khizhnjak_36
{
strings:
	$a0 = { 080388260903b900008b1603038b1e0503b80042cd217242ba1001b94203908b1e0503b440cd21 }


condition:
	$a0
}