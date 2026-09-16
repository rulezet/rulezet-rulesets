rule Win_Trojan_Chameleon_5
{
strings:
	$a0 = { 902bdbf59ef0b90508b8c129fd9efb909ef09b3180000048f990f0f89046e0ec909048904a05157bbdc428a297 }


condition:
	$a0
}