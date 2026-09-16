rule Win_Trojan_Trojan_286
{
strings:
	$a0 = { 4c4cff76fe33c050b80c0050b8020050e8170583c4088be55dc3558bec833e500d207505b8 }


condition:
	$a0
}