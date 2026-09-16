rule Win_Trojan_Gimon_3
{
strings:
	$a0 = { 0158050a03874406a30b03b440b90c008bd6cd21e8d501b440b9fb09ba0000cd21b43ecd2107 }


condition:
	$a0
}