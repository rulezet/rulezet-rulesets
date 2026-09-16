rule TTP_XOR_WriteProcessMemory_71f3 {
  strings:
    $key_71f3 = { 26 81 [2] 14 a3 [2] 12 96 [2] 3c 96 [2] 03 8a }

  condition:
    any of them
}