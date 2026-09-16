rule Win_Trojan_SillyOC_3
{
strings:
	$a0 = { 9600241f3c1f7506b44fcd21ebefba9e00b8023dcd2172e593b440b96400ba0001cd21b43ecd21 }


condition:
	$a0
}