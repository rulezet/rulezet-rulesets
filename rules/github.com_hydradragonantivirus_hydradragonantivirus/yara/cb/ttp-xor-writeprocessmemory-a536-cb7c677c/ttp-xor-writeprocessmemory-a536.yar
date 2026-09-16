rule TTP_XOR_WriteProcessMemory_a536 {
  strings:
    $key_a536 = { f2 44 [2] c0 66 [2] c6 53 [2] e8 53 [2] d7 4f }

  condition:
    any of them
}