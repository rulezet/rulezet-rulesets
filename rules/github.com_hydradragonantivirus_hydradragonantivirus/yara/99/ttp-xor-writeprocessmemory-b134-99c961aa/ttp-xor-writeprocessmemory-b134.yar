rule TTP_XOR_WriteProcessMemory_b134 {
  strings:
    $key_b134 = { e6 46 [2] d4 64 [2] d2 51 [2] fc 51 [2] c3 4d }

  condition:
    any of them
}