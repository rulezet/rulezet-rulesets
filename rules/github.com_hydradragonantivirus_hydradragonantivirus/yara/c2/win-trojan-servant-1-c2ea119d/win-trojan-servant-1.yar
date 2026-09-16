rule Win_Trojan_Servant_1
{
strings:
	$a0 = { b69b018dbec001b4e1cd2188660c8d76108dbec001b9b001ac32c4aae2fa }


condition:
	$a0
}