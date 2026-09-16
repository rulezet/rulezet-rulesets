rule Win_Trojan_Trivial_396
{
strings:
	$a0 = { 9e00cd218d8685068d9e0001b90001ba3a00be0f00e8170050b74093ba0001b13a9090cd21b44c }


condition:
	$a0
}