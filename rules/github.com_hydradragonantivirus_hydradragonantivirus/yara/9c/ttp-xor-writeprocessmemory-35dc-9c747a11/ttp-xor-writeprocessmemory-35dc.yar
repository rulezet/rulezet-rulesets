rule TTP_XOR_WriteProcessMemory_35dc {
  strings:
    $key_35dc = { 62 ae [2] 50 8c [2] 56 b9 [2] 78 b9 [2] 47 a5 }

  condition:
    any of them
}