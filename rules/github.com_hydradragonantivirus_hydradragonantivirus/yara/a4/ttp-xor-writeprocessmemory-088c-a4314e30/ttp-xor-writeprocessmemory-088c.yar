rule TTP_XOR_WriteProcessMemory_088c {
  strings:
    $key_088c = { 5f fe [2] 6d dc [2] 6b e9 [2] 45 e9 [2] 7a f5 }

  condition:
    any of them
}