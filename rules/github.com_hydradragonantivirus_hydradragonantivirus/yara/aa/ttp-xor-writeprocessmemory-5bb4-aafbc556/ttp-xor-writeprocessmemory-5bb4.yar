rule TTP_XOR_WriteProcessMemory_5bb4 {
  strings:
    $key_5bb4 = { 0c c6 [2] 3e e4 [2] 38 d1 [2] 16 d1 [2] 29 cd }

  condition:
    any of them
}