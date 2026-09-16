rule Win_Trojan_Killav_177
{
strings:
	$a0 = { 64656c20633a5c70726f6772616d646174615c2e636c616d77696e }

	$a1 = { 64656c[0-16]5c636c616d77696e }


condition:
	$a0 and $a1
}