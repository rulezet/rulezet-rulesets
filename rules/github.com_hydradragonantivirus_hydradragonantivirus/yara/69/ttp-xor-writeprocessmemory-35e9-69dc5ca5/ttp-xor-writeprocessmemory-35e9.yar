rule TTP_XOR_WriteProcessMemory_35e9 {
  strings:
    $key_35e9 = { 62 9b [2] 50 b9 [2] 56 8c [2] 78 8c [2] 47 90 }

  condition:
    any of them
}