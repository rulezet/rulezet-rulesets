rule TTP_XOR_WriteProcessMemory_5146 {
  strings:
    $key_5146 = { 06 34 [2] 34 16 [2] 32 23 [2] 1c 23 [2] 23 3f }

  condition:
    any of them
}