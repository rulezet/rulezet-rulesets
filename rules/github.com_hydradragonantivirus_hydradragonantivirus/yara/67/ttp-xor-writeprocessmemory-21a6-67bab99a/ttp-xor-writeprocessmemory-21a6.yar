rule TTP_XOR_WriteProcessMemory_21a6 {
  strings:
    $key_21a6 = { 76 d4 [2] 44 f6 [2] 42 c3 [2] 6c c3 [2] 53 df }

  condition:
    any of them
}