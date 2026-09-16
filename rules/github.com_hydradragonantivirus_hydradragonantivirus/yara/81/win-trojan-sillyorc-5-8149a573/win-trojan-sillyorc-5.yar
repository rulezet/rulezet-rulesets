rule Win_Trojan_SillyORC_5
{
strings:
	$a0 = { c0bf3c02be0001b90a00f3a6c30000000080fc3d74052eff2e38025056521e8bf2ac0ac074313c2e75f7ad0d20 }


condition:
	$a0
}