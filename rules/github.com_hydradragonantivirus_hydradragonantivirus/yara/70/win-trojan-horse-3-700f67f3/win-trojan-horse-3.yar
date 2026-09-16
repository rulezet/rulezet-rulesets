rule Win_Trojan_Horse_3
{
strings:
	$a0 = { 1e5a06c3e8f6ffcf9c2eff1e5206 }


condition:
	$a0
}