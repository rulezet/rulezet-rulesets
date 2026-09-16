rule TTP_XOR_WriteProcessMemory_5876 {
  strings:
    $key_5876 = { 0f 04 [2] 3d 26 [2] 3b 13 [2] 15 13 [2] 2a 0f }

  condition:
    any of them
}