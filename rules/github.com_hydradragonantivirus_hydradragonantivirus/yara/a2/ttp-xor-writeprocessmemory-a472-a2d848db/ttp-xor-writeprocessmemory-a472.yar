rule TTP_XOR_WriteProcessMemory_a472 {
  strings:
    $key_a472 = { f3 00 [2] c1 22 [2] c7 17 [2] e9 17 [2] d6 0b }

  condition:
    any of them
}