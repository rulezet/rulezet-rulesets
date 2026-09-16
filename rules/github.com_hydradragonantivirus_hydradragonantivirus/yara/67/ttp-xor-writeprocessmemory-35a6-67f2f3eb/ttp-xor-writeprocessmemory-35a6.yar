rule TTP_XOR_WriteProcessMemory_35a6 {
  strings:
    $key_35a6 = { 62 d4 [2] 50 f6 [2] 56 c3 [2] 78 c3 [2] 47 df }

  condition:
    any of them
}