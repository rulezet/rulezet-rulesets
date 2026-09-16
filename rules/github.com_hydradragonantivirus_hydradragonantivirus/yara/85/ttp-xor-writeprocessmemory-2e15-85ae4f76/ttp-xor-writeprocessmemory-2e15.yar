rule TTP_XOR_WriteProcessMemory_2e15 {
  strings:
    $key_2e15 = { 79 67 [2] 4b 45 [2] 4d 70 [2] 63 70 [2] 5c 6c }

  condition:
    any of them
}