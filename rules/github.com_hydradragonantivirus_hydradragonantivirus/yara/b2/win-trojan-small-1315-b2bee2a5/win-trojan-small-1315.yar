rule Win_Trojan_Small_1315
{
strings:
	$a0 = { 568d85fcfeffff50ff150c1040008bf085f6741f680020400056ff150810400085c074086a016a00ffd05959 }


condition:
	$a0
}