rule Win_Trojan_SillyC_211
{
strings:
	$a0 = { d402b00184077410b801438d16dd0230ed8a0f80f101 }


condition:
	$a0
}