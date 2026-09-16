rule Win_Trojan_VNuke_1
{
strings:
	$a0 = { 3f52fcffebe85f5e5b8be55dc30000ffffffff07000000302e302e302e3000ffffffff16000000205b564e756b652076312e3020427920566972 }


condition:
	$a0
}