rule TTP_XOR_WriteProcessMemory_a6a5 {
  strings:
    $key_a6a5 = { f1 d7 [2] c3 f5 [2] c5 c0 [2] eb c0 [2] d4 dc }

  condition:
    any of them
}