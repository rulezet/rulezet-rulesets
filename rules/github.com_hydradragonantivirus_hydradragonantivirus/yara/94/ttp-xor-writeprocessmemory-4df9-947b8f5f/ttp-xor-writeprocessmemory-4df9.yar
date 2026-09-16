rule TTP_XOR_WriteProcessMemory_4df9 {
  strings:
    $key_4df9 = { 1a 8b [2] 28 a9 [2] 2e 9c [2] 00 9c [2] 3f 80 }

  condition:
    any of them
}