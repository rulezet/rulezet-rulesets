rule Win_Trojan_Andromeda_14
{
strings:
	$a0 = { dfafb430cd2181ffc3c3751c8ccb2ea118032bd82e89 }


condition:
	$a0
}