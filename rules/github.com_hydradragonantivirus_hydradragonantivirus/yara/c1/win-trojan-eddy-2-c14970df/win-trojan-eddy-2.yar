rule Win_Trojan_Eddy_2
{
strings:
	$a0 = { b40f86e090cd213d01017504e83c0090b8213590cd21 }


condition:
	$a0
}