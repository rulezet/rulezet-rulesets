rule TTP_XOR_WriteProcessMemory_08dc {
  strings:
    $key_08dc = { 5f ae [2] 6d 8c [2] 6b b9 [2] 45 b9 [2] 7a a5 }

  condition:
    any of them
}