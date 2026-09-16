rule TTP_XOR_WriteProcessMemory_15a6 {
  strings:
    $key_15a6 = { 42 d4 [2] 70 f6 [2] 76 c3 [2] 58 c3 [2] 67 df }

  condition:
    any of them
}