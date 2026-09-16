rule Win_Trojan_Trivial_86
{
strings:
	$a0 = { 03012ec686cf0100b82435cd21b82425bac501cd218d96c901b44ee80e00cd2000bf0001578db62401a5a4c3b9 }


condition:
	$a0
}