rule TTP_XOR_WriteProcessMemory_a511 {
  strings:
    $key_a511 = { f2 63 [2] c0 41 [2] c6 74 [2] e8 74 [2] d7 68 }

  condition:
    any of them
}