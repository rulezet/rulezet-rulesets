rule TTP_XOR_WriteProcessMemory_5f26 {
  strings:
    $key_5f26 = { 08 54 [2] 3a 76 [2] 3c 43 [2] 12 43 [2] 2d 5f }

  condition:
    any of them
}