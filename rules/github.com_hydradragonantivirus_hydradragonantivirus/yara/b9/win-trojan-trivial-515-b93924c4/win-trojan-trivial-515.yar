rule Win_Trojan_Trivial_515
{
strings:
	$a0 = { 33c9ba8701cd217239b8003dba9e00cd2193b43fb90400ba8d01cd21b43ecd21803e9001027504b44febd5b8023d }


condition:
	$a0
}