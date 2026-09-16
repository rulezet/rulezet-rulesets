rule Win_Trojan_Hobbit_1
{
strings:
	$a0 = { 21268b4ffe5d554d33d2bf0100bb03008edd8b37468cdd518ed9030f413bcd75f7 }


condition:
	$a0
}