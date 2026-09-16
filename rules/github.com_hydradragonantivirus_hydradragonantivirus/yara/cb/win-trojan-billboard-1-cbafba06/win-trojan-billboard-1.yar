rule Win_Trojan_BillBoard_1
{
strings:
	$a0 = { fabf19018bf7ad355db0abadb103d2c8abeb00bf25018be758 }


condition:
	$a0
}