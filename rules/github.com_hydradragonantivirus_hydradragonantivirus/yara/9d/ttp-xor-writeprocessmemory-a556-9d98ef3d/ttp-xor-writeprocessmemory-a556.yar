rule TTP_XOR_WriteProcessMemory_a556 {
  strings:
    $key_a556 = { f2 24 [2] c0 06 [2] c6 33 [2] e8 33 [2] d7 2f }

  condition:
    any of them
}