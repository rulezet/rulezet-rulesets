rule Win_Trojan_MSO_1
{
strings:
	$a0 = { b9c506f3a4061fb82135cd21891ee4008c06e600bacd01b80325cd21bacd01b82125ccb86e72cc5e5f071f5881c6c1012bf75766a5c3 }


condition:
	$a0
}