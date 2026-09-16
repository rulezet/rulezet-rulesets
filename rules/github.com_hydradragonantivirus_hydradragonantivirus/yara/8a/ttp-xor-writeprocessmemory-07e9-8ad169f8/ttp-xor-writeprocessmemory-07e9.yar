rule TTP_XOR_WriteProcessMemory_07e9 {
  strings:
    $key_07e9 = { 50 9b [2] 62 b9 [2] 64 8c [2] 4a 8c [2] 75 90 }

  condition:
    any of them
}