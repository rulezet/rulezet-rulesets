rule TTP_XOR_WriteProcessMemory_188c {
  strings:
    $key_188c = { 4f fe [2] 7d dc [2] 7b e9 [2] 55 e9 [2] 6a f5 }

  condition:
    any of them
}