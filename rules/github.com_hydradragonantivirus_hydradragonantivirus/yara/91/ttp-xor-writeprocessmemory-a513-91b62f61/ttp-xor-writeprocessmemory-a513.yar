rule TTP_XOR_WriteProcessMemory_a513 {
  strings:
    $key_a513 = { f2 61 [2] c0 43 [2] c6 76 [2] e8 76 [2] d7 6a }

  condition:
    any of them
}