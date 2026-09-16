rule TTP_XOR_WriteProcessMemory_778c {
  strings:
    $key_778c = { 20 fe [2] 12 dc [2] 14 e9 [2] 3a e9 [2] 05 f5 }

  condition:
    any of them
}