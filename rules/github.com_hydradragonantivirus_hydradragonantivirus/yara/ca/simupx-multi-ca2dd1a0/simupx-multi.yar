rule simupx_multi
{
	meta:
		author = "PEiD"
		description = "Simple UPX Cryptor 30.4.2005 [Multi Layer] -> MANtiCORE"
		group = "999"
		function = "0"
	strings:
		$a0 = { 60 B8 ?? ?? ?? ?? B9 18 00 00 00 80 34 08 ?? E2 FA 61 68 ?? ?? ?? ?? C3 }
	condition:
		$a0
}