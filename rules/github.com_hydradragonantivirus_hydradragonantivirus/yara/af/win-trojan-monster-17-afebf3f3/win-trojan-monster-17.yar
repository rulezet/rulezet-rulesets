rule Win_Trojan_Monster_17
{
strings:
	$a0 = { b93502bede2cfc300446e2fb26e996ed8082839e99889fed9091cde7e3e7cde7e38e8280cd14bbe02400e6cdfde1 }


condition:
	$a0
}