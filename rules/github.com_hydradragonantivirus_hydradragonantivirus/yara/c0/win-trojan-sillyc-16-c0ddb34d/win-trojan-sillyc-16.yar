rule Win_Trojan_SillyC_16
{
strings:
	$a0 = { 2200cd21894401b16be814004848cd21b103e80b00b43e }


condition:
	$a0
}