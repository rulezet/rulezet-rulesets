rule TTP_XOR_WriteProcessMemory_e4a6 {
  strings:
    $key_e4a6 = { b3 d4 [2] 81 f6 [2] 87 c3 [2] a9 c3 [2] 96 df }

  condition:
    any of them
}