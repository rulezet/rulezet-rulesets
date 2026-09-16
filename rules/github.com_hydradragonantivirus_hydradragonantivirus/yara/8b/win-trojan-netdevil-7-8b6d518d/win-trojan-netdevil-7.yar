rule Win_Trojan_NetDevil_7
{
strings:
	$a0 = { 240603636c7306051cbdffffec2e061a2b20535552505249534520415353484f4c0f211f6fa1c301c51d7d }


condition:
	$a0
}