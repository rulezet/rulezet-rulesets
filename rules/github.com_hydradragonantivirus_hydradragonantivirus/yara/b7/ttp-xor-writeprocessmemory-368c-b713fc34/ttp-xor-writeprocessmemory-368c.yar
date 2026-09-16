rule TTP_XOR_WriteProcessMemory_368c {
  strings:
    $key_368c = { 61 fe [2] 53 dc [2] 55 e9 [2] 7b e9 [2] 44 f5 }

  condition:
    any of them
}