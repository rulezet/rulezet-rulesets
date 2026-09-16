rule PEiD_03444_WATCOM_C_C___Run_Time_system_DOS4GW_DOS_Extender_1988_93_ {
  meta:
    description = "[WATCOM C/C++ Run-Time system+DOS4GW DOS Extender 1988-93]"
    ep_only     = "true"

  strings:
    $a = { BF ?? ?? 8E D7 81 C4 ?? ?? BE ?? ?? 2B F7 8B C6 B1 ?? D3 }

  condition:
    $a
}