rule Win_Trojan_SillyC_14
{
strings:
	$a0 = { cd2189044eb169e813004848cd21b103e80a00b43e }


condition:
	$a0
}