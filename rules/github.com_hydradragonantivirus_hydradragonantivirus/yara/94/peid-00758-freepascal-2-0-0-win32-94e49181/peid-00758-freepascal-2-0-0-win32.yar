import "pe"
rule PEiD_00758_FreePascal_2_0_0_Win32_ {
  meta:
    description = "[FreePascal 2.0.0 Win32]"
    ep_only     = "true"

  strings:
    $a = { C6 05 00 80 40 00 01 E8 74 00 00 00 C6 05 00 80 40 00 00 E8 68 00 00 00 50 E8 00 00 00 00 FF 25 D8 A1 40 00 90 90 90 90 90 90 90 90 90 90 90 90 55 89 E5 83 EC 04 89 5D FC E8 92 00 00 00 E8 ED 00 00 00 89 C3 B9 ?? 70 40 00 89 DA B8 00 00 00 00 E8 0A 01 00 }

  condition:
    $a at pe.entry_point
}