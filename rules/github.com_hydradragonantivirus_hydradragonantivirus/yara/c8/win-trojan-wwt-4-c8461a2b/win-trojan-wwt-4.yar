rule Win_Trojan_WWT_4
{
strings:
	$a0 = { b90100cd217302eb10e80f00ba80 }


condition:
	$a0
}