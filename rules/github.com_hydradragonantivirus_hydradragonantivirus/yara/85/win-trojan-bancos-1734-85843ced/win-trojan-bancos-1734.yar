rule Win_Trojan_Bancos_1734
{
strings:
	$a0 = { 527f483671194d557525f220cdcd0afdf2f85946c66b879188a6973e8aaa7becde269e9779e1ae093f3c18c5cbae5c69d8bdd742e4ec5bfa2d39fb7f4c90aaab0b5faa358098 }


condition:
	$a0
}