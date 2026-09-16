rule TTP_XOR_WriteProcessMemory_4016 {
  strings:
    $key_4016 = { 17 64 [2] 25 46 [2] 23 73 [2] 0d 73 [2] 32 6f }

  condition:
    any of them
}