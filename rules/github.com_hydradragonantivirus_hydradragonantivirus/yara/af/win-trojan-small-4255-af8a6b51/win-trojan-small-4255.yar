rule Win_Trojan_Small_4255
{
strings:
	$a0 = { 68f256bafc5d01dd8d85932746038b44200050[0-120]8d3405000000008d743300 }


condition:
	$a0
}