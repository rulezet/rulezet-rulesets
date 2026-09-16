rule Win_Trojan_VGEN_117
{
strings:
	$a0 = { 83c20083ce0089c089db89c983e1ff83cb0089d289db89f683ce0083e5ff89c089db89ff83e5ff83cb0089f689db89ff }


condition:
	$a0
}