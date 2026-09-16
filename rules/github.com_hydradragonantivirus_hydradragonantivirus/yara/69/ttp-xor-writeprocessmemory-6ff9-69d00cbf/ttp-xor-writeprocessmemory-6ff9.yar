rule TTP_XOR_WriteProcessMemory_6ff9 {
  strings:
    $key_6ff9 = { 38 8b [2] 0a a9 [2] 0c 9c [2] 22 9c [2] 1d 80 }

  condition:
    any of them
}