rule TTP_XOR_WriteProcessMemory_a008 {
  strings:
    $key_a008 = { f7 7a [2] c5 58 [2] c3 6d [2] ed 6d [2] d2 71 }

  condition:
    any of them
}