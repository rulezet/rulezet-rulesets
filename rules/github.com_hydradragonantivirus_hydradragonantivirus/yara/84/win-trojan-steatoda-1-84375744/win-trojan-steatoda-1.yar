rule Win_Trojan_Steatoda_1
{
strings:
	$a0 = { 02c8b812032e8a164801505152bb00a0e891ff8ec0bbffffe889ff8bd85a5958cd13071f61c3 }


condition:
	$a0
}