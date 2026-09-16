rule Win_Trojan_DeltreeY_40
{
strings:
	$a0 = { 64656c747265652f7920633a0d0a }


condition:
	$a0
}