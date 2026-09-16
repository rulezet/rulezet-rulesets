rule TTP_XOR_WriteProcessMemory_b1e9 {
  strings:
    $key_b1e9 = { e6 9b [2] d4 b9 [2] d2 8c [2] fc 8c [2] c3 90 }

  condition:
    any of them
}