rule TTP_XOR_WriteProcessMemory_1e76 {
  strings:
    $key_1e76 = { 49 04 [2] 7b 26 [2] 7d 13 [2] 53 13 [2] 6c 0f }

  condition:
    any of them
}