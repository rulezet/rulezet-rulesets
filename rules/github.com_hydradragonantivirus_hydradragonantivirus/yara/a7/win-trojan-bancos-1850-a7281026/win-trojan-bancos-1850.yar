rule Win_Trojan_Bancos_1850
{
strings:
	$a0 = { 4e1b99984bca1860cedfea95c714e2772019657777754ea583e3c7cab4e08adfc16ee5b47ad368e1fd3dbfa0f1eb08468f89fc03eab847cfb1c5ce022fa623b9cb01a7bb0014 }


condition:
	$a0
}