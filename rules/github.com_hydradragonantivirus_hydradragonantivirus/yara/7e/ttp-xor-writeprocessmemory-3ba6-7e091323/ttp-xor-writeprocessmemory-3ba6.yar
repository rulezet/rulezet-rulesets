rule TTP_XOR_WriteProcessMemory_3ba6 {
  strings:
    $key_3ba6 = { 6c d4 [2] 5e f6 [2] 58 c3 [2] 76 c3 [2] 49 df }

  condition:
    any of them
}