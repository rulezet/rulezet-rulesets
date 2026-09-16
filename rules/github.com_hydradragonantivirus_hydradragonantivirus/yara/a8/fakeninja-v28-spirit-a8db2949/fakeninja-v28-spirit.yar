rule _FakeNinja_v28__Spirit_
{
	meta:
		description = "FakeNinja v2.8 -> Spirit"
	strings:
		$0 = {BA ?? ?? ?? ?? FF E2 64 11 40 00 FF 35 84 11 40 00 E8 40}
	condition:
		$0
}