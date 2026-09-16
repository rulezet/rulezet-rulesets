rule Win_Trojan_Squeaker_3
{
strings:
	$a0 = { 7f7503b480cf80fc4b74052eff2e2c005053521e06e0 }


condition:
	$a0
}