import "pe"
rule tElockv0951 : tE
{
	meta:
		author="_pusher_"
		date = "2015-11"
	strings:
		$a0 = { E9 D5 E4 FF FF }
	condition:
		$a0 at pe.entry_point
}