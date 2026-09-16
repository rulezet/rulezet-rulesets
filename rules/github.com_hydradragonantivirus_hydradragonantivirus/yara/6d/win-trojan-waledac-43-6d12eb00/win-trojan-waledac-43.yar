rule Win_Trojan_Waledac_43
{
strings:
	$a0 = { 80e23780e3da81f7b8cbb41f0ad4d3d2e9700700001337b58bc0c70ac1d11cd2e081ef4f }


condition:
	$a0
}