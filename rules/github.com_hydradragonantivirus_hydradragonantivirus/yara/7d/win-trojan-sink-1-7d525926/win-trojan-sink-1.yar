rule Win_Trojan_Sink_1
{
strings:
	$a0 = { e800005e83ee048b846901a300018b846b01a30201b800ffcd213dff00743ab82135cd21899c5b018c845d018cc848 }


condition:
	$a0
}