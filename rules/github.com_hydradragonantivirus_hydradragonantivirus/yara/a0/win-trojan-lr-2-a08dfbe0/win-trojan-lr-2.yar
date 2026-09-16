rule Win_Trojan_LR_2
{
strings:
	$a0 = { 37a7226f68f69a1c014ca9c05a45a9b6b8d9f8b9132537ccd31c530453cf5932991d561ae6afeeed }


condition:
	$a0
}