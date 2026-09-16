rule TTP_XOR_WriteProcessMemory_7f16 {
  strings:
    $key_7f16 = { 28 64 [2] 1a 46 [2] 1c 73 [2] 32 73 [2] 0d 6f }

  condition:
    any of them
}