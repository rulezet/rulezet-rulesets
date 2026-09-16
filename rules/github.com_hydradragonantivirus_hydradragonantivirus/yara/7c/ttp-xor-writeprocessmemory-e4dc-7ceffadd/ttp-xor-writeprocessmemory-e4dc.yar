rule TTP_XOR_WriteProcessMemory_e4dc {
  strings:
    $key_e4dc = { b3 ae [2] 81 8c [2] 87 b9 [2] a9 b9 [2] 96 a5 }

  condition:
    any of them
}