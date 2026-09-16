rule Win_Trojan_Stoned_20
{
strings:
	$a0 = { 03cd13e99100e4210c02e6218bd9b90100ba8001b80102cd1326c6470d00b80103cd13fec5b8 }


condition:
	$a0
}