rule TTP_XOR_WriteProcessMemory_4816 {
  strings:
    $key_4816 = { 1f 64 [2] 2d 46 [2] 2b 73 [2] 05 73 [2] 3a 6f }

  condition:
    any of them
}