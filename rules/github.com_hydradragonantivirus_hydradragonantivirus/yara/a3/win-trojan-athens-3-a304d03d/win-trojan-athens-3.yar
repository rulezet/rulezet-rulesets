rule Win_Trojan_Athens_3
{
strings:
	$a0 = { ed0890fc0e1fbe280003f58bfe1e07b9f1053e8a9e0800ac32c3aae2fa }


condition:
	$a0
}