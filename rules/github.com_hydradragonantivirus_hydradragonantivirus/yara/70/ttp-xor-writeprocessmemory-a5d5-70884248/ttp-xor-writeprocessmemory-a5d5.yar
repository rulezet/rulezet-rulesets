rule TTP_XOR_WriteProcessMemory_a5d5 {
  strings:
    $key_a5d5 = { f2 a7 [2] c0 85 [2] c6 b0 [2] e8 b0 [2] d7 ac }

  condition:
    any of them
}