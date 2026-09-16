rule Win_Trojan_Bancos_1903
{
strings:
	$a0 = { e98796323ed5acf6067d8ddd77a13e8d36d02376c346da0b8ebb280aa3ac6be077801df542488b0e720f80a1e3dd17a35c23428a2779dca314212ec2c23cd8016c134afa01dd }


condition:
	$a0
}