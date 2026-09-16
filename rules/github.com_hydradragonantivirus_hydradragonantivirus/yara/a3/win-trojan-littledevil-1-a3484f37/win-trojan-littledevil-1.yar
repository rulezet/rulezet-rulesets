rule Win_Trojan_LittleDevil_1
{
strings:
	$a0 = { 7906be3d08bf0000b90d00fcf3a4b440b93d0833d2e8f4fd7303e9ce00b8004233c933d2e8e5fd }


condition:
	$a0
}