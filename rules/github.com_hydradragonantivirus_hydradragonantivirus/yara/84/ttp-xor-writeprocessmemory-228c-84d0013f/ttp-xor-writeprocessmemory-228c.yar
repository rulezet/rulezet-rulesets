rule TTP_XOR_WriteProcessMemory_228c {
  strings:
    $key_228c = { 75 fe [2] 47 dc [2] 41 e9 [2] 6f e9 [2] 50 f5 }

  condition:
    any of them
}