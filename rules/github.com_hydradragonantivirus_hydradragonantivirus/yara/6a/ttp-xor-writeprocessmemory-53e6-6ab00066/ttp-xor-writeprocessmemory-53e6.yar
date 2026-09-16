rule TTP_XOR_WriteProcessMemory_53e6 {
  strings:
    $key_53e6 = { 04 94 [2] 36 b6 [2] 30 83 [2] 1e 83 [2] 21 9f }

  condition:
    any of them
}