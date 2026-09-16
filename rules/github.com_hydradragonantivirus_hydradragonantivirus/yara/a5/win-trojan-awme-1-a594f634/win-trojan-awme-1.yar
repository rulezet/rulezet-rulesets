rule Win_Trojan_AWME_1
{
strings:
	$a0 = { b923090f4b8e6e7b358c8d339ca40db93e700f4b8e6e7b }


condition:
	$a0
}