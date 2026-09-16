rule Win_Trojan_Typer_2
{
strings:
	$a0 = { 2166b82e636f6de87f0166b82e657865e8760133c08ed8f6066c041f0e1f7514be000133c0e770 }


condition:
	$a0
}