rule TTP_XOR_WriteProcessMemory_31b0 {
  strings:
    $key_31b0 = { 66 c2 [2] 54 e0 [2] 52 d5 [2] 7c d5 [2] 43 c9 }

  condition:
    any of them
}