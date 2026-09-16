rule TTP_XOR_WriteProcessMemory_11dc {
  strings:
    $key_11dc = { 46 ae [2] 74 8c [2] 72 b9 [2] 5c b9 [2] 63 a5 }

  condition:
    any of them
}