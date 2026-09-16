rule TTP_XOR_WriteProcessMemory_44dc {
  strings:
    $key_44dc = { 13 ae [2] 21 8c [2] 27 b9 [2] 09 b9 [2] 36 a5 }

  condition:
    any of them
}