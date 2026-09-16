rule _VIRUS__IWormHybris_
{
	meta:
		description = "VIRUS - I-Worm.Hybris"
	strings:
		$0 = {EB 16 A8 54 ?? ?? 47 41 42 4C 4B 43 47 43 ?? ?? ?? ?? ?? ?? 52 49 53 ?? FC 68 4C 70 40 ?? FF 15}
	condition:
		$0
}