import "pe"
rule _Symantec_C_v210_v400_or_Zortech_C_v30r1_
{
	meta:
		description = "Symantec C v2.10, v4.00 or Zortech C v3.0r1"
	strings:
		$0 = {FA FC B8 ?? ?? 8E D8}
	condition:
		$0 at pe.entry_point
}