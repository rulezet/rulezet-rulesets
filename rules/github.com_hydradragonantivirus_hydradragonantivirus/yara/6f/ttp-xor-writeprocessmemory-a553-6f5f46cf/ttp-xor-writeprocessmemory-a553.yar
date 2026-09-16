rule TTP_XOR_WriteProcessMemory_a553 {
  strings:
    $key_a553 = { f2 21 [2] c0 03 [2] c6 36 [2] e8 36 [2] d7 2a }

  condition:
    any of them
}