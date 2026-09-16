rule Win_Trojan_Zhengxi_2
{
strings:
	$a0 = { b06ff7c7634f7d0412c7b3db81dd5ba581d3e174d3d01e03febdf0f13bf2bf02008edf2bc9b4629cff1e64001fbe }


condition:
	$a0
}