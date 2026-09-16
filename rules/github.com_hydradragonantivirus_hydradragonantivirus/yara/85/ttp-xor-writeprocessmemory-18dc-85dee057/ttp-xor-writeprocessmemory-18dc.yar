rule TTP_XOR_WriteProcessMemory_18dc {
  strings:
    $key_18dc = { 4f ae [2] 7d 8c [2] 7b b9 [2] 55 b9 [2] 6a a5 }

  condition:
    any of them
}