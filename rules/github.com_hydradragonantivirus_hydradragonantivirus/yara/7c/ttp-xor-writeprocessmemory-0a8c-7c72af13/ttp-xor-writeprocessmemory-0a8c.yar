rule TTP_XOR_WriteProcessMemory_0a8c {
  strings:
    $key_0a8c = { 5d fe [2] 6f dc [2] 69 e9 [2] 47 e9 [2] 78 f5 }

  condition:
    any of them
}