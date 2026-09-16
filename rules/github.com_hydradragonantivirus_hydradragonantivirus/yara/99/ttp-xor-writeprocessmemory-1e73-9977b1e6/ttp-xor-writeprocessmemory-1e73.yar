rule TTP_XOR_WriteProcessMemory_1e73 {
  strings:
    $key_1e73 = { 49 01 [2] 7b 23 [2] 7d 16 [2] 53 16 [2] 6c 0a }

  condition:
    any of them
}