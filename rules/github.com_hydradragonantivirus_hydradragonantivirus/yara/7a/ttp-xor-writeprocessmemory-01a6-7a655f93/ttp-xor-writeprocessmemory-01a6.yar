rule TTP_XOR_WriteProcessMemory_01a6 {
  strings:
    $key_01a6 = { 56 d4 [2] 64 f6 [2] 62 c3 [2] 4c c3 [2] 73 df }

  condition:
    any of them
}