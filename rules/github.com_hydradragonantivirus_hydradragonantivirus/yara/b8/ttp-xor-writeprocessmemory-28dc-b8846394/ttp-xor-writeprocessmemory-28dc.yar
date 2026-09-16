rule TTP_XOR_WriteProcessMemory_28dc {
  strings:
    $key_28dc = { 7f ae [2] 4d 8c [2] 4b b9 [2] 65 b9 [2] 5a a5 }

  condition:
    any of them
}