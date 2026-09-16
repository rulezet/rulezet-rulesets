rule Win_Trojan_Communist_1
{
strings:
	$a0 = { e2facd21b44033c9cd21b43ecd218cc02e03869c050510002e89869c05b87919cd213d97190f84 }


condition:
	$a0
}