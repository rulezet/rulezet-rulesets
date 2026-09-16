import "pe"
rule _WATCOM_CCpp_RunTime_systempDOS4GW_DOS_Extender_198893_
{
	meta:
		description = "WATCOM C/C++ Run-Time system+DOS4GW DOS Extender 1988-93"
	strings:
		$0 = {BF ?? ?? 8E D7 81 C4 ?? ?? BE ?? ?? 2B F7 8B C6 B1 ?? D3}
	condition:
		$0 at pe.entry_point
}