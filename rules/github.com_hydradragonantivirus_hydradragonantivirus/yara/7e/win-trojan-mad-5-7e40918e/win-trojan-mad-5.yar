rule Win_Trojan_MAD_5
{
strings:
	$a0 = { a302732b9da62ca4a32d23a3d896fefc56eaa3f3fba3a34824f8b8a489a12b87b0d8c4b91c09c1a4 }


condition:
	$a0
}