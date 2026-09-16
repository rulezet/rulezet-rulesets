rule TTP_XOR_WriteProcessMemory_1e56 {
  strings:
    $key_1e56 = { 49 24 [2] 7b 06 [2] 7d 33 [2] 53 33 [2] 6c 2f }

  condition:
    any of them
}