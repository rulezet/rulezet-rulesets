import "pe"
rule tElockv092a1 : tE
{
	meta:
		author="_pusher_"
		date = "2015-11"
	strings:
		$a0 = { E9 6E E7 FF FF }
	condition:
		$a0 at pe.entry_point
}