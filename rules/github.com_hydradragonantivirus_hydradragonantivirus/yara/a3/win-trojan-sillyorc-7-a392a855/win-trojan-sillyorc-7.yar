rule Win_Trojan_SillyORC_7
{
strings:
	$a0 = { 8ec0bf44028bec8b76008bee81c64100b90a00f3a6c30000000080fc3d74052eff2e40025056521e8bf2ac0ac074 }


condition:
	$a0
}