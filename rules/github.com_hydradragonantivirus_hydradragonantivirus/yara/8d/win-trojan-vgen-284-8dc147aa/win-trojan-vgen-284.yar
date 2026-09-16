rule Win_Trojan_VGEN_284
{
strings:
	$a0 = { ba009a0d0058005589e531c09acd02ba00bf52011e57bf00000e579ae602ba00bf52011e579a6e03ba009a9102 }


condition:
	$a0
}