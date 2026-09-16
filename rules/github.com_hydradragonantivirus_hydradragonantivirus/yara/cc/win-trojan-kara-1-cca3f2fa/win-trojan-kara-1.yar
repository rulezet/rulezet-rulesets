rule Win_Trojan_Kara_1
{
strings:
	$a0 = { 0100b9e302b44099cd638bcab80042cd63b440b108ba4901cd63b80057cd6340cd63b43ecd6359 }


condition:
	$a0
}