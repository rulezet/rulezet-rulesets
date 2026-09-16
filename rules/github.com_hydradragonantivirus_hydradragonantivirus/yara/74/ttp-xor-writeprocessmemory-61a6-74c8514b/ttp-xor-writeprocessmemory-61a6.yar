rule TTP_XOR_WriteProcessMemory_61a6 {
  strings:
    $key_61a6 = { 36 d4 [2] 04 f6 [2] 02 c3 [2] 2c c3 [2] 13 df }

  condition:
    any of them
}