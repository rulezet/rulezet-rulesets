rule Win_Trojan_K_22
{
strings:
	$a0 = { b80042cd217236ba1001b9f70290b440cd217229b90000ba00008b1ed902b000b442cd217217 }


condition:
	$a0
}