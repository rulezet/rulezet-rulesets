rule TTP_XOR_WriteProcessMemory_a591 {
  strings:
    $key_a591 = { f2 e3 [2] c0 c1 [2] c6 f4 [2] e8 f4 [2] d7 e8 }

  condition:
    any of them
}