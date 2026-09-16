rule Win_Trojan_VB_1670
{
strings:
	$a0 = { 7361756469656e7400000000dd975f27e56db04a }


condition:
	$a0
}