import "pe"
rule tElockvhsm7x : tE
{
	meta:
		author="_pusher_"
		date = "2015-11"
	strings:
		$a0 = { 60 E8 ?? ?? ?? ?? C3 83 }
	condition:
		$a0 at pe.entry_point
}