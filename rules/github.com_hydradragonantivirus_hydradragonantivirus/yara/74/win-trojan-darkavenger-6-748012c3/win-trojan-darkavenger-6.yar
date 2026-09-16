rule Win_Trojan_DarkAvenger_6
{
strings:
	$a0 = { e800005e81ee39078bfe56501e060e1f0e07b200b93607ac5188d1d2c8fec259aae2f407 }


condition:
	$a0
}