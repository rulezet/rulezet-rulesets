import "pe"
rule _Turbo_Profiler_Areas_file_
{
	meta:
		description = "Turbo Profiler Areas file"
	strings:
		$0 = {54 75 72 62 6F ?? 50 72 6F 66 69 6C 65 72 ?? 61 72 65 61 73 ?? 66 69 6C 65}
	condition:
		$0 at pe.entry_point
}