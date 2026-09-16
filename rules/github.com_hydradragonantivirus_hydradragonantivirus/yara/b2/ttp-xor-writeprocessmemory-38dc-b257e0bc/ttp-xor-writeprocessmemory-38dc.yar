rule TTP_XOR_WriteProcessMemory_38dc {
  strings:
    $key_38dc = { 6f ae [2] 5d 8c [2] 5b b9 [2] 75 b9 [2] 4a a5 }

  condition:
    any of them
}