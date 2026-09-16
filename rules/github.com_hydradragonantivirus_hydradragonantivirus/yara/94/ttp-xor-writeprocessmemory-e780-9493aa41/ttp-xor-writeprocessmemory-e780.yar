rule TTP_XOR_WriteProcessMemory_e780 {
  strings:
    $key_e780 = { b0 f2 [2] 82 d0 [2] 84 e5 [2] aa e5 [2] 95 f9 }

  condition:
    any of them
}