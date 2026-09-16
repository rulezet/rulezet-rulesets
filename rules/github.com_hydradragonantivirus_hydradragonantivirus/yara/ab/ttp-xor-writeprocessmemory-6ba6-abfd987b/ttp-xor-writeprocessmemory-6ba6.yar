rule TTP_XOR_WriteProcessMemory_6ba6 {
  strings:
    $key_6ba6 = { 3c d4 [2] 0e f6 [2] 08 c3 [2] 26 c3 [2] 19 df }

  condition:
    any of them
}