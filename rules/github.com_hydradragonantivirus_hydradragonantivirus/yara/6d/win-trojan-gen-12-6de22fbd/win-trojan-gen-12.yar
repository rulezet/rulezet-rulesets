rule Win_Trojan_Gen_12
{
strings:
	$a0 = { 0f00bad009cd21b8004233c999cd21b440b92500baeb08cd21c3b440b95a00ba9108cd2153 }


condition:
	$a0
}