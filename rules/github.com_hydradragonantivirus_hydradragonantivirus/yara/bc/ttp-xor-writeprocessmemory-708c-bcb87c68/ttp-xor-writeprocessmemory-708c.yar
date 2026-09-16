rule TTP_XOR_WriteProcessMemory_708c {
  strings:
    $key_708c = { 27 fe [2] 15 dc [2] 13 e9 [2] 3d e9 [2] 02 f5 }

  condition:
    any of them
}