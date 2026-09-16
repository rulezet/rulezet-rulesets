rule PEiD_01252_MZ0oPE_1_0_6b____TaskFall_ {
  meta:
    description = "[MZ0oPE 1.0.6b -> TaskFall]"
    ep_only     = "true"

  strings:
    $a = { EB CA 89 03 83 C3 04 87 FE 32 C0 AE 75 FD 87 FE 80 3E FF 75 E2 46 5B 83 C3 04 53 8B 1B 80 3F FF 75 C9 8B E5 61 68 ?? ?? ?? ?? C3 FC B2 80 33 DB A4 B3 02 E8 6D 00 00 00 73 F6 33 C9 E8 64 00 00 00 73 1C 33 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 }

  condition:
    $a
}