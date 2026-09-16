rule Win_Trojan_Demiurg_1
{
strings:
	$a0 = { 8bf45007501ffb8bd8832e130407b106cd12d3e0ba80008ec0b90b00b8070206cd13bac80a }


condition:
	$a0
}