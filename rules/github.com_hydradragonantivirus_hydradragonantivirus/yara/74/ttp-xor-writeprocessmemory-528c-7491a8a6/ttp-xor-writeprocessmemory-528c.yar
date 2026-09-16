rule TTP_XOR_WriteProcessMemory_528c {
  strings:
    $key_528c = { 05 fe [2] 37 dc [2] 31 e9 [2] 1f e9 [2] 20 f5 }

  condition:
    any of them
}