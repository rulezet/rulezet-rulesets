rule TTP_XOR_WriteProcessMemory_5016 {
  strings:
    $key_5016 = { 07 64 [2] 35 46 [2] 33 73 [2] 1d 73 [2] 22 6f }

  condition:
    any of them
}