rule TTP_XOR_WriteProcessMemory_1e75 {
  strings:
    $key_1e75 = { 49 07 [2] 7b 25 [2] 7d 10 [2] 53 10 [2] 6c 0c }

  condition:
    any of them
}