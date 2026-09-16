rule TTP_XOR_WriteProcessMemory_15dc {
  strings:
    $key_15dc = { 42 ae [2] 70 8c [2] 76 b9 [2] 58 b9 [2] 67 a5 }

  condition:
    any of them
}