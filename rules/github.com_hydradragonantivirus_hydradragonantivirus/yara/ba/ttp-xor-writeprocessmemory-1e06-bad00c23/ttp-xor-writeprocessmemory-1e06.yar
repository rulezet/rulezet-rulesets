rule TTP_XOR_WriteProcessMemory_1e06 {
  strings:
    $key_1e06 = { 49 74 [2] 7b 56 [2] 7d 63 [2] 53 63 [2] 6c 7f }

  condition:
    any of them
}