rule Win_Trojan_Pox_4
{
strings:
	$a0 = { 4b455d553e8a865f02b93a022e304600f6d045e2f7c3 }


condition:
	$a0
}