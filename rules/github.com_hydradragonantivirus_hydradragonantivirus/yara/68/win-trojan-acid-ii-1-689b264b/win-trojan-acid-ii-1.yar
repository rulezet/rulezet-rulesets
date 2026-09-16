rule Win_Trojan_Acid_II_1
{
strings:
	$a0 = { 80042e89168d02b430cd218b2e02008b1e2c008edaa392008c069000891e8c00892ea800e88101c43e8a008bc78bd8 }


condition:
	$a0
}