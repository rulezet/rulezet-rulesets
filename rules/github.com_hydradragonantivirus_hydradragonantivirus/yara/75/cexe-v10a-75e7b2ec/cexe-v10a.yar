import "pe"
rule _CExe_v10a_
{
	meta:
		description = "CExe v1.0a"
	strings:
		$0 = {53 60 BD 8D 45 8D 5D E8}
	condition:
		$0 at pe.entry_point
}