import "pe"
rule mpress_071_212_Net : Matcode
{
	meta:
		author="_pusher_"
		date = "2016-06"
	strings:
		$a1 = { 21 49 74 27 73 20 2E 4E 45 54 20 45 58 45 24 }
	condition:
		$a1 at 45 and
		(pe.imports ("mscoree.dll","_CorExeMain") or pe.imports ("mscoree.dll","_CorDllMain"))
}