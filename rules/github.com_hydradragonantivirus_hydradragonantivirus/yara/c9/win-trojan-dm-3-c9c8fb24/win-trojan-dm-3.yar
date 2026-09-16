rule Win_Trojan_DM_3
{
strings:
	$a0 = { 21ff03f5bf0002b93601f3a4061fbe }


condition:
	$a0
}