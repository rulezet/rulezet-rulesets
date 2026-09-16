rule TTP_XOR_WriteProcessMemory_b2b0 {
  strings:
    $key_b2b0 = { e5 c2 [2] d7 e0 [2] d1 d5 [2] ff d5 [2] c0 c9 }

  condition:
    any of them
}