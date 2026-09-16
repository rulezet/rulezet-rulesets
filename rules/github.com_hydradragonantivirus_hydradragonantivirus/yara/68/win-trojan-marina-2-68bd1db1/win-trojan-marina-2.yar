rule Win_Trojan_Marina_2
{
strings:
	$a0 = { 60683b01be0000b93e0031b400004646e2f8c3 }


condition:
	$a0
}