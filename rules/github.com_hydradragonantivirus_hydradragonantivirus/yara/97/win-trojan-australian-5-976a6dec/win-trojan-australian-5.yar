rule Win_Trojan_Australian_5
{
strings:
	$a0 = { 3005b44eba7001e90600b43ecd21b44fcd217244b8023dba9e00cd218bd8ba00f0b97600b43fcd21803e00f0bd74db }


condition:
	$a0
}