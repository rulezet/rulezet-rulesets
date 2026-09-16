rule Win_Trojan_Secrets_1
{
strings:
	$a0 = { 0601040d1400a20601c3bb3e01a006010ac0740b30074302c781fb58037ef5c3 }


condition:
	$a0
}