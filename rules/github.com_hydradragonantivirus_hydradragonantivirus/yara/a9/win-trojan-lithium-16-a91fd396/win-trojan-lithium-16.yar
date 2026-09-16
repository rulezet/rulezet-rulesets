rule Win_Trojan_Lithium_16
{
strings:
	$a0 = { 111b3873755dc0f51aae767a9613bc6da35df669134c0dbc75fae8fb52e96c73706ba4654d73670b433a5e7c6f396e7570000b49ac5f7aa1d55af7f80f47ea122167f49a9d94bd65eebbec40bbecac0f4dcb5d0f }


condition:
	$a0
}