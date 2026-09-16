rule TTP_XOR_WriteProcessMemory_1e16 {
  strings:
    $key_1e16 = { 49 64 [2] 7b 46 [2] 7d 73 [2] 53 73 [2] 6c 6f }

  condition:
    any of them
}