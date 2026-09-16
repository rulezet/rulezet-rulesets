rule TTP_XOR_WriteProcessMemory_3d8c {
  strings:
    $key_3d8c = { 6a fe [2] 58 dc [2] 5e e9 [2] 70 e9 [2] 4f f5 }

  condition:
    any of them
}