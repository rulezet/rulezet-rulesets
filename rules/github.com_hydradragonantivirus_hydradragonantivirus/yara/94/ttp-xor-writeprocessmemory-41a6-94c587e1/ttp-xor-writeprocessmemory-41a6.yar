rule TTP_XOR_WriteProcessMemory_41a6 {
  strings:
    $key_41a6 = { 16 d4 [2] 24 f6 [2] 22 c3 [2] 0c c3 [2] 33 df }

  condition:
    any of them
}