rule Win_Trojan_Fakealert_115
{
strings:
	$a0 = { 8d6424fc893c24e98bfcffff558d6424088a4c2c18e877f2ffff558d64 }

	$a1 = { 976441676568bd657767 }


condition:
	$a0 and $a1
}