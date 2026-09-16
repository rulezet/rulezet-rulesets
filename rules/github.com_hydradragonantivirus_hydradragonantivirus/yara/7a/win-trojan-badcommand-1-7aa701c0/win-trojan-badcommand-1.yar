rule Win_Trojan_BadCommand_1
{
strings:
	$a0 = { 5b83eb03fa8bcb81e900018be381c42d005e83ec045883ec04fc300446e2fbe977fe }


condition:
	$a0
}