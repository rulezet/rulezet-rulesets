rule Win_Trojan_Bzz_2
{
strings:
	$a0 = { 8bf4830409908b34c387f581ed0f018db62c012e8a245680f4908bfeb9f800ac32c4aae2fa }


condition:
	$a0
}