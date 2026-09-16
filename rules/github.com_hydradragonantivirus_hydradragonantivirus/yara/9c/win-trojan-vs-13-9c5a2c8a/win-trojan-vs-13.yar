rule Win_Trojan_VS_13
{
strings:
	$a0 = { a31c038cd02ea31a030500018ed09c53515256571e068cc88ed82b06b000a3b000b430cd213c03720b33c08ed8803e }


condition:
	$a0
}