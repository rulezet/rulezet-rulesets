rule TTP_XOR_WriteProcessMemory_a076 {
  strings:
    $key_a076 = { f7 04 [2] c5 26 [2] c3 13 [2] ed 13 [2] d2 0f }

  condition:
    any of them
}