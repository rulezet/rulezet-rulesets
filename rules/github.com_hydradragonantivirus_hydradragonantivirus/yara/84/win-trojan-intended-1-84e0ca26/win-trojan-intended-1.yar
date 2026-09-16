rule Win_Trojan_Intended_1
{
strings:
	$a0 = { eb00e80000cc5d81ed05012efe862b012e80be320100741c0e0e071f8db634018bfe2e8a9e3301b99402ac2fd8aae2fa }


condition:
	$a0
}