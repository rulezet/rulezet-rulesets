rule Win_Trojan_Caco_1
{
strings:
	$a0 = { b803fecd215e33d25681fb454675232e3aac920b771f }


condition:
	$a0
}