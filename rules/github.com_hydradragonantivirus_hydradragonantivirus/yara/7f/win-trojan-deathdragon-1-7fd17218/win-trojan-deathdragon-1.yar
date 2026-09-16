rule Win_Trojan_DeathDragon_1
{
strings:
	$a0 = { 595d81ed0601bf0001578db6f302a4a5b85346b9050033dbcd2f3dffff750bb85346b90500bb0100cd2fb80fff }


condition:
	$a0
}