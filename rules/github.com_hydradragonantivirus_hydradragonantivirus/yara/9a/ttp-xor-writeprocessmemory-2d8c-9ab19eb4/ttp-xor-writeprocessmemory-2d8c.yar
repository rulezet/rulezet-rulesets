rule TTP_XOR_WriteProcessMemory_2d8c {
  strings:
    $key_2d8c = { 7a fe [2] 48 dc [2] 4e e9 [2] 60 e9 [2] 5f f5 }

  condition:
    any of them
}