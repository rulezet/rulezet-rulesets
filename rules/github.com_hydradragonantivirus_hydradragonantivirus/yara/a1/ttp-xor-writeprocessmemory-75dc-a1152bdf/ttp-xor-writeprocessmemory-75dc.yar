rule TTP_XOR_WriteProcessMemory_75dc {
  strings:
    $key_75dc = { 22 ae [2] 10 8c [2] 16 b9 [2] 38 b9 [2] 07 a5 }

  condition:
    any of them
}