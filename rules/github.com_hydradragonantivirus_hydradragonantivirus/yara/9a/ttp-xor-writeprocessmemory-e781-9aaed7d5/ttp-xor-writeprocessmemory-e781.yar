rule TTP_XOR_WriteProcessMemory_e781 {
  strings:
    $key_e781 = { b0 f3 [2] 82 d1 [2] 84 e4 [2] aa e4 [2] 95 f8 }

  condition:
    any of them
}