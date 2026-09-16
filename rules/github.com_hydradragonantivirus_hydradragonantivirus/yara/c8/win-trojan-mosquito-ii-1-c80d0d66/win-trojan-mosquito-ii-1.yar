rule Win_Trojan_Mosquito_II_1
{
strings:
	$a0 = { bae602b90300cd21ba0000b002e8b700b440ba0301b9fd01cd21b43ecd21b80143268b0e0001 }


condition:
	$a0
}