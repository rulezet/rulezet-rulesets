rule TTP_XOR_WriteProcessMemory_738c {
  strings:
    $key_738c = { 24 fe [2] 16 dc [2] 10 e9 [2] 3e e9 [2] 01 f5 }

  condition:
    any of them
}