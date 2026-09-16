rule Win_Trojan_StayCool_1
{
strings:
	$a0 = { 0e4801b440b93d0299cd217302722db80042b9000099cd21b440b90500ba4701cd217218b801 }


condition:
	$a0
}