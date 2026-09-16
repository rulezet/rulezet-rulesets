rule TTP_XOR_WriteProcessMemory_478c {
  strings:
    $key_478c = { 10 fe [2] 22 dc [2] 24 e9 [2] 0a e9 [2] 35 f5 }

  condition:
    any of them
}