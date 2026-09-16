rule TTP_XOR_WriteProcessMemory_4700 {
  strings:
    $key_4700 = { 10 72 [2] 22 50 [2] 24 65 [2] 0a 65 [2] 35 79 }

  condition:
    any of them
}