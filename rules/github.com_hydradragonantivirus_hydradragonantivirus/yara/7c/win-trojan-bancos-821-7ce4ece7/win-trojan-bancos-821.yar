rule Win_Trojan_Bancos_821
{
strings:
	$a0 = { d34abd7007bb6a9de5283456aae2e708fbc7158662c461d00dcd2d0fe16897124a5bed8225498c39557b0f77dfb00ccdc713250ffeb4f92e471151a5432b372e4df5466fa703 }


condition:
	$a0
}