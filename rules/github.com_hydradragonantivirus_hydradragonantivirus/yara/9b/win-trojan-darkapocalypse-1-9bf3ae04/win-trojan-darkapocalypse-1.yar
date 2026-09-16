rule Win_Trojan_DarkApocalypse_1
{
strings:
	$a0 = { 42cd210500018986cb0233c088a6f703b9f8038bd5b440cd21e86affb90f008d96c802b440cd21 }


condition:
	$a0
}