rule TTP_XOR_WriteProcessMemory_e2a1 {
  strings:
    $key_e2a1 = { b5 d3 [2] 87 f1 [2] 81 c4 [2] af c4 [2] 90 d8 }

  condition:
    any of them
}