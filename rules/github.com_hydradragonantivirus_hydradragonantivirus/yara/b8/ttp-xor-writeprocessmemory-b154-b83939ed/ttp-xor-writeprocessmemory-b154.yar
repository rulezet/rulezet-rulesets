rule TTP_XOR_WriteProcessMemory_b154 {
  strings:
    $key_b154 = { e6 26 [2] d4 04 [2] d2 31 [2] fc 31 [2] c3 2d }

  condition:
    any of them
}