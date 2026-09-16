import "pe"
rule _StarForce_V3X__StarForce_Copy_Protection_System_
{
	meta:
		description = "StarForce V3.X -> StarForce Copy Protection System"
	strings:
		$0 = {68 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? 00 00 00 00 00}
	condition:
		$0 at pe.entry_point
}