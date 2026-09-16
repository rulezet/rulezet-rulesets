rule TTP_XOR_WriteProcessMemory_1e55 {
  strings:
    $key_1e55 = { 49 27 [2] 7b 05 [2] 7d 30 [2] 53 30 [2] 6c 2c }

  condition:
    any of them
}