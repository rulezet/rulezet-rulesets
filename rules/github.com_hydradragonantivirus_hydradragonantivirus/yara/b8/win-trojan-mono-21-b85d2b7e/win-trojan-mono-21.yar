rule Win_Trojan_Mono_21
{
strings:
	$a0 = { 8bc98bc990908bc98bdb8bd2908bc9908bd28bc990908bc98bc9908bc98bd290908bd28bd28bc98bc9908bc98bc990908bc98b }


condition:
	$a0
}