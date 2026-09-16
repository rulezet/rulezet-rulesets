rule TTP_XOR_WriteProcessMemory_5826 {
  strings:
    $key_5826 = { 0f 54 [2] 3d 76 [2] 3b 43 [2] 15 43 [2] 2a 5f }

  condition:
    any of them
}