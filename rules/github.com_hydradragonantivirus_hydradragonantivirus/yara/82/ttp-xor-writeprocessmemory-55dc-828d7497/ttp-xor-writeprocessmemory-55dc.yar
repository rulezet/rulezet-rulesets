rule TTP_XOR_WriteProcessMemory_55dc {
  strings:
    $key_55dc = { 02 ae [2] 30 8c [2] 36 b9 [2] 18 b9 [2] 27 a5 }

  condition:
    any of them
}