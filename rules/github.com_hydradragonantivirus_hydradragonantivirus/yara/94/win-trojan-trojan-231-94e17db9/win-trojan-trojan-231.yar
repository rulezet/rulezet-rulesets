rule Win_Trojan_Trojan_231
{
strings:
	$a0 = { ed0801fa8cd08bd880ef108ed38ed0fb8db60103bf2fce81ef2fcdfca5a5a4b48f80c4a6b0dd0444e8c501899efd }


condition:
	$a0
}