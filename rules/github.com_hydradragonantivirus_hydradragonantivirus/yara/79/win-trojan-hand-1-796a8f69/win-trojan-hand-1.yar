rule Win_Trojan_Hand_1
{
strings:
	$a0 = { 79219a00006c009a00000a005589e531c09a7c026c00bf44001e57bf00000e579a92026c00bf }


condition:
	$a0
}