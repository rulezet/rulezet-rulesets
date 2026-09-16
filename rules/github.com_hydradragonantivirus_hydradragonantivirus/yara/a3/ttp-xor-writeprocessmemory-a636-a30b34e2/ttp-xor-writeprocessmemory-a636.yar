rule TTP_XOR_WriteProcessMemory_a636 {
  strings:
    $key_a636 = { f1 44 [2] c3 66 [2] c5 53 [2] eb 53 [2] d4 4f }

  condition:
    any of them
}