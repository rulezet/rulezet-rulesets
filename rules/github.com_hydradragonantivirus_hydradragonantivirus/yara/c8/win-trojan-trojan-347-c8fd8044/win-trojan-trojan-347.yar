rule Win_Trojan_Trojan_347
{
strings:
	$a0 = { ae009a00004c005589e5b800049a7c02ae0081ec00049ac0014c0031c0a35e00b001509a57024c00bf76011e57 }


condition:
	$a0
}