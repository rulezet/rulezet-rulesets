rule TTP_XOR_WriteProcessMemory_e2a6 {
  strings:
    $key_e2a6 = { b5 d4 [2] 87 f6 [2] 81 c3 [2] af c3 [2] 90 df }

  condition:
    any of them
}