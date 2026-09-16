rule TTP_XOR_WriteProcessMemory_20a6 {
  strings:
    $key_20a6 = { 77 d4 [2] 45 f6 [2] 43 c3 [2] 6d c3 [2] 52 df }

  condition:
    any of them
}