rule TTP_XOR_WriteProcessMemory_a476 {
  strings:
    $key_a476 = { f3 04 [2] c1 26 [2] c7 13 [2] e9 13 [2] d6 0f }

  condition:
    any of them
}