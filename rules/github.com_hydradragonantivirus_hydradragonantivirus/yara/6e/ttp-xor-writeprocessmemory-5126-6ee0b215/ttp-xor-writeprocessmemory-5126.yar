rule TTP_XOR_WriteProcessMemory_5126 {
  strings:
    $key_5126 = { 06 54 [2] 34 76 [2] 32 43 [2] 1c 43 [2] 23 5f }

  condition:
    any of them
}