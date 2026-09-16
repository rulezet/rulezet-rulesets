rule TTP_XOR_WriteProcessMemory_1819 {
  strings:
    $key_1819 = { 4f 6b [2] 7d 49 [2] 7b 7c [2] 55 7c [2] 6a 60 }

  condition:
    any of them
}