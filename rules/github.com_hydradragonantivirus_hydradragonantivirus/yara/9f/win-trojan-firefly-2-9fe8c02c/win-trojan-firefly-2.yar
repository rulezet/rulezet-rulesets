rule Win_Trojan_Firefly_2
{
strings:
	$a0 = { 01b910018137411d817702c0f983c304e2f2 }


condition:
	$a0
}