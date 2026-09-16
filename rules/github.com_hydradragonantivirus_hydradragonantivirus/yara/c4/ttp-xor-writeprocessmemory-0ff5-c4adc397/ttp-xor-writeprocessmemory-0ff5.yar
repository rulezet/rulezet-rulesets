rule TTP_XOR_WriteProcessMemory_0ff5 {
  strings:
    $key_0ff5 = { 58 87 [2] 6a a5 [2] 6c 90 [2] 42 90 [2] 7d 8c }

  condition:
    any of them
}