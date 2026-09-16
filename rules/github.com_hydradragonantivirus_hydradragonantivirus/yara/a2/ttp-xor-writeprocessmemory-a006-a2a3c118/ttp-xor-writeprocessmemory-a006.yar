rule TTP_XOR_WriteProcessMemory_a006 {
  strings:
    $key_a006 = { f7 74 [2] c5 56 [2] c3 63 [2] ed 63 [2] d2 7f }

  condition:
    any of them
}