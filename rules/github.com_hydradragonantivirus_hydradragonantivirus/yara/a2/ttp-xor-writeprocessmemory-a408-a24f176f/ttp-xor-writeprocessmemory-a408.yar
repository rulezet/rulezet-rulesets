rule TTP_XOR_WriteProcessMemory_a408 {
  strings:
    $key_a408 = { f3 7a [2] c1 58 [2] c7 6d [2] e9 6d [2] d6 71 }

  condition:
    any of them
}