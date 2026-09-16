rule TTP_XOR_WriteProcessMemory_45dc {
  strings:
    $key_45dc = { 12 ae [2] 20 8c [2] 26 b9 [2] 08 b9 [2] 37 a5 }

  condition:
    any of them
}