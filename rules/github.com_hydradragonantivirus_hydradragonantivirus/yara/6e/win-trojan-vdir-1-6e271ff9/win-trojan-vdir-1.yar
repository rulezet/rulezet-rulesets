rule Win_Trojan_Vdir_1
{
strings:
	$a0 = { 0157e80100e95e81c6bd00eb0390e803fc56a5a5a5a55e81eeb000c704a5a5c74402a5a5b8013ebbadfecd2181f3 }


condition:
	$a0
}