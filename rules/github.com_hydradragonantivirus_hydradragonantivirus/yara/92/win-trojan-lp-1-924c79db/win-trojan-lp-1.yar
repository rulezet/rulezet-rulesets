rule Win_Trojan_LP_1
{
strings:
	$a0 = { 125e33ff4853a31304bdc000d3e0578ec087468e89426aa0100483ee1124303c30b87a0087468c }


condition:
	$a0
}