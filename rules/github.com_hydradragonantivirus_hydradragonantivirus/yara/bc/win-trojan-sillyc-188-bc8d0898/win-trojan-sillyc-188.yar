rule Win_Trojan_SillyC_188
{
strings:
	$a0 = { c88ed88b1601015b53b97201b440cd21723eba0000b900 }


condition:
	$a0
}