rule TTP_XOR_WriteProcessMemory_578c {
  strings:
    $key_578c = { 00 fe [2] 32 dc [2] 34 e9 [2] 1a e9 [2] 25 f5 }

  condition:
    any of them
}