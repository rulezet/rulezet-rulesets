rule TTP_XOR_WriteProcessMemory_e68c {
  strings:
    $key_e68c = { b1 fe [2] 83 dc [2] 85 e9 [2] ab e9 [2] 94 f5 }

  condition:
    any of them
}