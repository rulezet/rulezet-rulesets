rule Win_Trojan_Kiwi_1
{
strings:
	$a0 = { 1e068cc88ed82b06b300a3b300b430cd213c03720b33c08ed8803e12044b7503eb5990b44abbffffcd2183eb26b44a }


condition:
	$a0
}