rule TTP_XOR_WriteProcessMemory_668c {
  strings:
    $key_668c = { 31 fe [2] 03 dc [2] 05 e9 [2] 2b e9 [2] 14 f5 }

  condition:
    any of them
}