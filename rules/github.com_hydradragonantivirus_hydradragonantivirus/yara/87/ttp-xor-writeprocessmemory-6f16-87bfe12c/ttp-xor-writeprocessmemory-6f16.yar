rule TTP_XOR_WriteProcessMemory_6f16 {
  strings:
    $key_6f16 = { 38 64 [2] 0a 46 [2] 0c 73 [2] 22 73 [2] 1d 6f }

  condition:
    any of them
}