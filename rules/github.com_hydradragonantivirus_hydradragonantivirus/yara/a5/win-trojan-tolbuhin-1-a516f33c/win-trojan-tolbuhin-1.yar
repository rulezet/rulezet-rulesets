rule Win_Trojan_Tolbuhin_1
{
strings:
	$a0 = { 0cb0e98805478b1eb208268b4f1a4141890d4747b84b5389052e8b1e330cb8004231c931d2e8 }


condition:
	$a0
}