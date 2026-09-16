rule Win_Trojan_SillyC_38
{
strings:
	$a0 = { 02e82d00a38a015a59b440cd21b000e81f008bd759b440cd21b43ecd21ba00ffb44fcd21 }


condition:
	$a0
}