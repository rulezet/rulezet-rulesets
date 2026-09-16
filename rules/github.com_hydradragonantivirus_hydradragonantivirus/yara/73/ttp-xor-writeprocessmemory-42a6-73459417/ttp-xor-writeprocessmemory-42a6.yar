rule TTP_XOR_WriteProcessMemory_42a6 {
  strings:
    $key_42a6 = { 15 d4 [2] 27 f6 [2] 21 c3 [2] 0f c3 [2] 30 df }

  condition:
    any of them
}