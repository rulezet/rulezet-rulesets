rule Win_Trojan_C_47
{
strings:
	$a0 = { 3000894c10895412e81200b440ba000159cd21b43ecd21b44fe940ffc38b4c055149494646e80a }


condition:
	$a0
}