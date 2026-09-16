rule TTP_XOR_WriteProcessMemory_0e15 {
  strings:
    $key_0e15 = { 59 67 [2] 6b 45 [2] 6d 70 [2] 43 70 [2] 7c 6c }

  condition:
    any of them
}