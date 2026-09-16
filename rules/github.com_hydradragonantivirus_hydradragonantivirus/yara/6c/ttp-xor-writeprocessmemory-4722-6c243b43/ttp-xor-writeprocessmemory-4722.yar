rule TTP_XOR_WriteProcessMemory_4722 {
  strings:
    $key_4722 = { 10 50 [2] 22 72 [2] 24 47 [2] 0a 47 [2] 35 5b }

  condition:
    any of them
}