rule TTP_XOR_WriteProcessMemory_72a6 {
  strings:
    $key_72a6 = { 25 d4 [2] 17 f6 [2] 11 c3 [2] 3f c3 [2] 00 df }

  condition:
    any of them
}