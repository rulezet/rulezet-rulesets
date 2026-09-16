rule Win_Trojan_W_229
{
strings:
	$a0 = { a0150105dfff977f645065724f6245746e6974790061784e756d62651dffffffffdbcc3104186c1af39fb65b489d3008 }


condition:
	$a0
}