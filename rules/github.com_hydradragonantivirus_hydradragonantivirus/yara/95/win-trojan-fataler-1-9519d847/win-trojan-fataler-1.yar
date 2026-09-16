rule Win_Trojan_Fataler_1
{
strings:
	$a0 = { 96be6801cd96b8007dcdec80c70660000100cd35e8cdec46cd81c70660000100cdec64be3801cd }


condition:
	$a0
}