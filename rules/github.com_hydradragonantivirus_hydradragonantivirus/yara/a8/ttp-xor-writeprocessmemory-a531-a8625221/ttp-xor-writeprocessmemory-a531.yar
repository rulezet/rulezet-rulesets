rule TTP_XOR_WriteProcessMemory_a531 {
  strings:
    $key_a531 = { f2 43 [2] c0 61 [2] c6 54 [2] e8 54 [2] d7 48 }

  condition:
    any of them
}