rule Win_Trojan_VB_1293
{
strings:
	$a0 = { 5c73795374736d6532334e5c746f70656461652e6578326e44 }


condition:
	$a0
}