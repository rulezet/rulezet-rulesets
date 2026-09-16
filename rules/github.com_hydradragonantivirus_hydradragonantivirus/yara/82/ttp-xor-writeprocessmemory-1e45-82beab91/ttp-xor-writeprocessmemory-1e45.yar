rule TTP_XOR_WriteProcessMemory_1e45 {
  strings:
    $key_1e45 = { 49 37 [2] 7b 15 [2] 7d 20 [2] 53 20 [2] 6c 3c }

  condition:
    any of them
}