rule TTP_XOR_WriteProcessMemory_ea26 {
  strings:
    $key_ea26 = { bd 54 [2] 8f 76 [2] 89 43 [2] a7 43 [2] 98 5f }

  condition:
    any of them
}