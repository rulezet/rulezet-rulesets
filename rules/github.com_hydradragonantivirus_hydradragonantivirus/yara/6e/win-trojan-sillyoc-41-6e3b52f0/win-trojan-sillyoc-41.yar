rule Win_Trojan_SillyOC_41
{
strings:
	$a0 = { 2801cd21721eb43db002ba9e00cd219333d2fec6b440b9340090cd21b43ecd21b44febdec32a }


condition:
	$a0
}