rule mew10
{
	meta:
		author = "PEiD"
		description = "MEW 10 1.0 -> NorthFox/HCC"
		group = "444"
		function = "14"
	strings:
		$a0 = { 33 C0 E9 ?? ?? ?? FF }
	condition:
		$a0
}