rule TTP_XOR_WriteProcessMemory_788c {
  strings:
    $key_788c = { 2f fe [2] 1d dc [2] 1b e9 [2] 35 e9 [2] 0a f5 }

  condition:
    any of them
}