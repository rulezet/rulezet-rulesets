rule Win_Trojan_Rsw_2
{
strings:
	$a0 = { fa01268a85d51630e448a20202a00300c43efa01268885d516bf38021e57b8d51631d252509a }


condition:
	$a0
}