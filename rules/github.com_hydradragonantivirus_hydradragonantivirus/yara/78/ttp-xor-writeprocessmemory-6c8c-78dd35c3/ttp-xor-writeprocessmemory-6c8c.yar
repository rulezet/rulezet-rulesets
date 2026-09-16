rule TTP_XOR_WriteProcessMemory_6c8c {
  strings:
    $key_6c8c = { 3b fe [2] 09 dc [2] 0f e9 [2] 21 e9 [2] 1e f5 }

  condition:
    any of them
}