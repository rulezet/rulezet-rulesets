rule Win_Trojan_SillyRC_5
{
strings:
	$a0 = { 01018b354f5703f7a5a433c08ec003ffa674184e4fb98a00f3a48ed8be8400bf0c00a5a5b82125ba3702cc0e1f0e07 }


condition:
	$a0
}