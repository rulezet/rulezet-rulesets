rule Win_Trojan_Dikshev_10
{
strings:
	$a0 = { 4d50b8434f50b82a2e50545ab44ecd21721eb8323d2c3099b29ecd2193b44099fec633c9b136cd21b43e }


condition:
	$a0
}