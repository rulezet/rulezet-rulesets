rule TTP_XOR_WriteProcessMemory_1e65 {
  strings:
    $key_1e65 = { 49 17 [2] 7b 35 [2] 7d 00 [2] 53 00 [2] 6c 1c }

  condition:
    any of them
}