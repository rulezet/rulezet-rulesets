rule TTP_XOR_WriteProcessMemory_71f8 {
  strings:
    $key_71f8 = { 26 8a [2] 14 a8 [2] 12 9d [2] 3c 9d [2] 03 81 }

  condition:
    any of them
}