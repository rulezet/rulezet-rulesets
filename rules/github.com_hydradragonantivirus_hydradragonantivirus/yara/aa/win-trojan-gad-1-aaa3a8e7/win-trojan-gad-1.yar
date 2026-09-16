rule Win_Trojan_Gad_1
{
strings:
	$a0 = { 8bfe8bb47302b975025651f3a4595f2ac0f3aacbe807004761642d666c79fc5e81ee1900bf0001b8cffdcd213cfc }


condition:
	$a0
}