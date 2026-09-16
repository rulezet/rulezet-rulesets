rule TTP_XOR_WriteProcessMemory_46a6 {
  strings:
    $key_46a6 = { 11 d4 [2] 23 f6 [2] 25 c3 [2] 0b c3 [2] 34 df }

  condition:
    any of them
}