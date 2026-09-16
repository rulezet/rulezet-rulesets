rule Win_Trojan_Androm_3
{
strings:
	$a0 = { ba22390000558bec83ec0ca198da40000905a4da4000c745f803eff20df7d8c745fc02eff20d810566d140005ad14000 }


condition:
	$a0
}