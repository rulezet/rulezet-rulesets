rule Win_Trojan_TinyDI_3
{
strings:
	$a0 = { 023dcd218bd8061f8bd749b43fcd21056c005033c9b800 }


condition:
	$a0
}