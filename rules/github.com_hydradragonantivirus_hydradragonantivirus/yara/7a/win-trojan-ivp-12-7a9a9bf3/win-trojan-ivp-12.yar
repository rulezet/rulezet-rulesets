rule Win_Trojan_IVP_12
{
strings:
	$a0 = { e2fdba9302ffd2c353ba8002ffd25bb440b99301ba0001cd2153ba8002ffd25bc3 }


condition:
	$a0
}