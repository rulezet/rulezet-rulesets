rule Win_Trojan_Opwin_2
{
strings:
	$a0 = { c5f8aed6a03be5719d5938640f404f5057494e3a434c3a459d542e1c58a55d399c4a31e12c1f4fa2d85a5e511375be64b3ef8dbfce7676ae171472095fa5c63b }


condition:
	$a0
}