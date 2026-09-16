rule Win_Trojan_VGEN_282
{
strings:
	$a0 = { 81ed1201bf00018db60c01a4a5b44e8d960301cd212e803ea4004474082e803e960033750ab44fcd213c12745febe6 }


condition:
	$a0
}