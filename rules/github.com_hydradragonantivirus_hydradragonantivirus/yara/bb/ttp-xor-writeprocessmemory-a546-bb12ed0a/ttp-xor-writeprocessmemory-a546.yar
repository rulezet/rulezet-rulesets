rule TTP_XOR_WriteProcessMemory_a546 {
  strings:
    $key_a546 = { f2 34 [2] c0 16 [2] c6 23 [2] e8 23 [2] d7 3f }

  condition:
    any of them
}