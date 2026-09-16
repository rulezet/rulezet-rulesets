rule TTP_XOR_WriteProcessMemory_b151 {
  strings:
    $key_b151 = { e6 23 [2] d4 01 [2] d2 34 [2] fc 34 [2] c3 28 }

  condition:
    any of them
}