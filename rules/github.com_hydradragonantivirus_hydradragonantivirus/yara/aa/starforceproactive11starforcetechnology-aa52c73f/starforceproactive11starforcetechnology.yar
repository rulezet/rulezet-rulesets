import "pe"
rule StarForceProActive11StarForceTechnology
	{
	strings:
			$a0 = { 68 ?? ?? ?? ?? FF 25 ?? ?? 57 }

	condition:
			$a0 at (pe.entry_point)
	}