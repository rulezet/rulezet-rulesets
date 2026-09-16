rule TTP_XOR_WriteProcessMemory_a510 {
  strings:
    $key_a510 = { f2 62 [2] c0 40 [2] c6 75 [2] e8 75 [2] d7 69 }

  condition:
    any of them
}