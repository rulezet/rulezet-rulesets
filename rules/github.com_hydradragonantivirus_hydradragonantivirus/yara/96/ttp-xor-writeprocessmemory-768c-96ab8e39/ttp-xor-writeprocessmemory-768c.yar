rule TTP_XOR_WriteProcessMemory_768c {
  strings:
    $key_768c = { 21 fe [2] 13 dc [2] 15 e9 [2] 3b e9 [2] 04 f5 }

  condition:
    any of them
}