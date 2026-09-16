rule PEiD_01035_Microsoft__R__Incremental_Linker_Version_5_12_8078__MASM_TASM__ {
  meta:
    description = "[Microsoft (R) Incremental Linker Version 5.12.8078 (MASM/TASM)]"
    ep_only     = "false"

  strings:
    $a = { 6A 00 68 00 30 40 00 68 1E 30 40 00 6A 00 E8 0D 00 00 00 6A 00 E8 00 00 00 00 FF 25 00 20 40 00 FF 25 08 20 40 }

  condition:
    $a
}