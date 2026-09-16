rule TTP_XOR_WriteProcessMemory_58f6 {
  strings:
    $key_58f6 = { 0f 84 [2] 3d a6 [2] 3b 93 [2] 15 93 [2] 2a 8f }

  condition:
    any of them
}