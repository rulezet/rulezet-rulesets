rule Win_Trojan_V_21
{
strings:
	$a0 = { 02bb0002cd1372b02e803efb01807403e8d602a14c0026a30004a14e0026a30204c7064c00ba }


condition:
	$a0
}