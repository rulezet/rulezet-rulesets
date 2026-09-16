rule TTP_XOR_WriteProcessMemory_7d8c {
  strings:
    $key_7d8c = { 2a fe [2] 18 dc [2] 1e e9 [2] 30 e9 [2] 0f f5 }

  condition:
    any of them
}