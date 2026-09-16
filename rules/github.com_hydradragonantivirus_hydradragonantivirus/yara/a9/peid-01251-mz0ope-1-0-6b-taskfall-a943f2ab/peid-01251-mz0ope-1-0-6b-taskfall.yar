rule PEiD_01251_MZ0oPE_1_0_6b____TaskFall_ {
  meta:
    description = "[MZ0oPE 1.0.6b -> TaskFall]"
    ep_only     = "true"

  strings:
    $a = { EB CA 89 03 83 C3 04 87 FE 32 C0 AE 75 FD 87 FE 80 3E FF 75 E2 46 5B 83 C3 04 53 8B 1B 80 3F FF 75 C9 8B E5 61 68 ?? ?? ?? ?? C3 }

  condition:
    $a
}