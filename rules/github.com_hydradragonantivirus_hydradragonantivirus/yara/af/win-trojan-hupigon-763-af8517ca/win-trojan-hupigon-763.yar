rule Win_Trojan_Hupigon_763
{
strings:
	$a0 = { 70c27acd01d0d3ea73f6f289b136eaaec909f8fe55e568de61f9de463bffa8bf6347101a9935ddaa4bf881c596b9cf454924a7d3153760c7f41d4082080c1b6a753bcbd16641baac1840cb715a3a }


condition:
	$a0
}