rule TTP_XOR_WriteProcessMemory_5c8c {
  strings:
    $key_5c8c = { 0b fe [2] 39 dc [2] 3f e9 [2] 11 e9 [2] 2e f5 }

  condition:
    any of them
}