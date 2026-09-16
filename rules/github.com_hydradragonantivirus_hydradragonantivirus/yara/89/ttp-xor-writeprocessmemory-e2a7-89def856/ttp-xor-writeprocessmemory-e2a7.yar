rule TTP_XOR_WriteProcessMemory_e2a7 {
  strings:
    $key_e2a7 = { b5 d5 [2] 87 f7 [2] 81 c2 [2] af c2 [2] 90 de }

  condition:
    any of them
}