rule TTP_XOR_WriteProcessMemory_22a6 {
  strings:
    $key_22a6 = { 75 d4 [2] 47 f6 [2] 41 c3 [2] 6f c3 [2] 50 df }

  condition:
    any of them
}