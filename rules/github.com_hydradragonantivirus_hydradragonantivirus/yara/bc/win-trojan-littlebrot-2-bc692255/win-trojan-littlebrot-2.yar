rule Win_Trojan_LittleBrot_2
{
strings:
	$a0 = { 03b844008ec0bf00018bf7b94101f3a48ed9be8400bf4102ba8b01ad3bc27409aba5061fb82125cd210e1f0e07bb3000b44acd218e062c00bf0000b5ff }


condition:
	$a0
}