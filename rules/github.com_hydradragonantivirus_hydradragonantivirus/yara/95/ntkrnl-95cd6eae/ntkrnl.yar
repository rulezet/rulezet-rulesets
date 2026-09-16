rule ntkrnl
{
	meta:
		author = "PEiD"
		description = "NTKrnl Security Suite -> NTKrnl Team"
		group = "133"
		function = "18"
	strings:
		$a0 = { 68 ?? ?? ?? ?? E8 01 00 00 00 C3 C3 }
	condition:
		$a0
}