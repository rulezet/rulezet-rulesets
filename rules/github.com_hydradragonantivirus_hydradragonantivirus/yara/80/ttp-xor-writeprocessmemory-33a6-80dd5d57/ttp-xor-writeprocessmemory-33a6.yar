rule TTP_XOR_WriteProcessMemory_33a6 {
  strings:
    $key_33a6 = { 64 d4 [2] 56 f6 [2] 50 c3 [2] 7e c3 [2] 41 df }

  condition:
    any of them
}