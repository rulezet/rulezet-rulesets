rule TTP_XOR_WriteProcessMemory_e7a1 {
  strings:
    $key_e7a1 = { b0 d3 [2] 82 f1 [2] 84 c4 [2] aa c4 [2] 95 d8 }

  condition:
    any of them
}