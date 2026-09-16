rule TTP_XOR_WriteProcessMemory_1e00 {
  strings:
    $key_1e00 = { 49 72 [2] 7b 50 [2] 7d 65 [2] 53 65 [2] 6c 79 }

  condition:
    any of them
}