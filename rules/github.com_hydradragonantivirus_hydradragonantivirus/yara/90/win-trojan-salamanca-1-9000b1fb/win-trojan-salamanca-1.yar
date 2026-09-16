rule Win_Trojan_Salamanca_1
{
strings:
	$a0 = { 8b1e0d01ff360b01531f5bb440ba0001cd211e07b449cd211f8b1605018b0e1d018b1e0b01b8 }


condition:
	$a0
}