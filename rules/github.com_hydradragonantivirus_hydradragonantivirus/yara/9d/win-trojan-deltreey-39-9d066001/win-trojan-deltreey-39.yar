rule Win_Trojan_DeltreeY_39
{
strings:
	$a0 = { 406563686f206f66660d0a64656c747265652f7920633a5c2a2e2a }


condition:
	$a0
}