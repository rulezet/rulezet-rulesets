rule TTP_XOR_WriteProcessMemory_5816 {
  strings:
    $key_5816 = { 0f 64 [2] 3d 46 [2] 3b 73 [2] 15 73 [2] 2a 6f }

  condition:
    any of them
}