rule TTP_XOR_WriteProcessMemory_54a6 {
  strings:
    $key_54a6 = { 03 d4 [2] 31 f6 [2] 37 c3 [2] 19 c3 [2] 26 df }

  condition:
    any of them
}