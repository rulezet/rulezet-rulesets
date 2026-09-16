rule TTP_XOR_WriteProcessMemory_3bb4 {
  strings:
    $key_3bb4 = { 6c c6 [2] 5e e4 [2] 58 d1 [2] 76 d1 [2] 49 cd }

  condition:
    any of them
}