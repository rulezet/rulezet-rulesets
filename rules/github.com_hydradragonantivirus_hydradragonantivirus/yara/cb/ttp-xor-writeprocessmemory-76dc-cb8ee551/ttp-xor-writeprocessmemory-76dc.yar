rule TTP_XOR_WriteProcessMemory_76dc {
  strings:
    $key_76dc = { 21 ae [2] 13 8c [2] 15 b9 [2] 3b b9 [2] 04 a5 }

  condition:
    any of them
}