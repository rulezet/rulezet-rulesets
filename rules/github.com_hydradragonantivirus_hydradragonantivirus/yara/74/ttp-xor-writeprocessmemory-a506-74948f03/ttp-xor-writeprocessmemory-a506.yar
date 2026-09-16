rule TTP_XOR_WriteProcessMemory_a506 {
  strings:
    $key_a506 = { f2 74 [2] c0 56 [2] c6 63 [2] e8 63 [2] d7 7f }

  condition:
    any of them
}