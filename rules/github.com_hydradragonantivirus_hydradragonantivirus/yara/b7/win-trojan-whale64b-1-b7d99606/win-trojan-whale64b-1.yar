rule Win_Trojan_Whale64B_1
{
strings:
	$a0 = { 43e80000920e921f365b575081eba023 }


condition:
	$a0
}