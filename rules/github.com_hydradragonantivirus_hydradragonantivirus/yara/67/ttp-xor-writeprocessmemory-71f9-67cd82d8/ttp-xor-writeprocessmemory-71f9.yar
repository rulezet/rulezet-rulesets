rule TTP_XOR_WriteProcessMemory_71f9 {
  strings:
    $key_71f9 = { 26 8b [2] 14 a9 [2] 12 9c [2] 3c 9c [2] 03 80 }

  condition:
    any of them
}