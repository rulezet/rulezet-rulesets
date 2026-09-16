rule Win_Trojan_BAT_87
{
strings:
	$a0 = { 72656e202a2e[0-3]202a2e70756e }

	$a1 = { 64656c202a2e6c6e6b }


condition:
	$a0 and $a1
}