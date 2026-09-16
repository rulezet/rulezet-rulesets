rule Win_Trojan_SillyOC_5
{
strings:
	$a0 = { 9e00cd2193b440b92404ba0001cd21b43ecd21b44febdcb44e33c9bab003cd21721bb8023d }


condition:
	$a0
}