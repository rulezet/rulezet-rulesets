rule Win_Trojan_VGEN_406
{
strings:
	$a0 = { b8455992929292e80000cc5d81ed10012efe8637012e80be3f0100741e0e0e071f8db641018bfe2e8a9e4001b9 }


condition:
	$a0
}