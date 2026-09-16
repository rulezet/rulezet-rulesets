rule Win_Trojan_SGEN_6
{
strings:
	$a0 = { b903b42fcd21b80200f7e301c680340046e2 }


condition:
	$a0
}