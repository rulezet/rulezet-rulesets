rule TTP_XOR_WriteProcessMemory_72dc {
  strings:
    $key_72dc = { 25 ae [2] 17 8c [2] 11 b9 [2] 3f b9 [2] 00 a5 }

  condition:
    any of them
}