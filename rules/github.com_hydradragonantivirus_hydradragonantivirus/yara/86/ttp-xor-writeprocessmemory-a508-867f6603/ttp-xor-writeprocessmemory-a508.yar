rule TTP_XOR_WriteProcessMemory_a508 {
  strings:
    $key_a508 = { f2 7a [2] c0 58 [2] c6 6d [2] e8 6d [2] d7 71 }

  condition:
    any of them
}