rule TTP_XOR_WriteProcessMemory_52dc {
  strings:
    $key_52dc = { 05 ae [2] 37 8c [2] 31 b9 [2] 1f b9 [2] 20 a5 }

  condition:
    any of them
}