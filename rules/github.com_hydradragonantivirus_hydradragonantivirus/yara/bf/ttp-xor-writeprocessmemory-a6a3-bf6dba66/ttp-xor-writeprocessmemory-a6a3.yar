rule TTP_XOR_WriteProcessMemory_a6a3 {
  strings:
    $key_a6a3 = { f1 d1 [2] c3 f3 [2] c5 c6 [2] eb c6 [2] d4 da }

  condition:
    any of them
}