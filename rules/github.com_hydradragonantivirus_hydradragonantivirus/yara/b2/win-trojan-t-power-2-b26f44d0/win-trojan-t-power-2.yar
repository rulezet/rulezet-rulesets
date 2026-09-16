rule Win_Trojan_T_Power_2
{
strings:
	$a0 = { 6a046a0c6a001f8d8680015f89058c4d028d8684015f89058c4d020e1f0e07fdb940088d }


condition:
	$a0
}