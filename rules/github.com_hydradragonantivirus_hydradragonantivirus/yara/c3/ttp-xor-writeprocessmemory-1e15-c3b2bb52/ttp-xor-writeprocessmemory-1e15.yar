rule TTP_XOR_WriteProcessMemory_1e15 {
  strings:
    $key_1e15 = { 49 67 [2] 7b 45 [2] 7d 70 [2] 53 70 [2] 6c 6c }

  condition:
    any of them
}