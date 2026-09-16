rule TTP_XOR_WriteProcessMemory_1bb4 {
  strings:
    $key_1bb4 = { 4c c6 [2] 7e e4 [2] 78 d1 [2] 56 d1 [2] 69 cd }

  condition:
    any of them
}