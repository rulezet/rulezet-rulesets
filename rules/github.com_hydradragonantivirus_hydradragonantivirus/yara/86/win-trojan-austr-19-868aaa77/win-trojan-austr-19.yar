rule Win_Trojan_Austr_19
{
strings:
	$a0 = { 33c9ba4402cd21725c8bd8ba4501b90500b43fcd21 }


condition:
	$a0
}