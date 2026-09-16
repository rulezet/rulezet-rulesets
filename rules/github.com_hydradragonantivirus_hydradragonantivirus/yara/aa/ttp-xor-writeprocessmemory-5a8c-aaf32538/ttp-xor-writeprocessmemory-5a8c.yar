rule TTP_XOR_WriteProcessMemory_5a8c {
  strings:
    $key_5a8c = { 0d fe [2] 3f dc [2] 39 e9 [2] 17 e9 [2] 28 f5 }

  condition:
    any of them
}