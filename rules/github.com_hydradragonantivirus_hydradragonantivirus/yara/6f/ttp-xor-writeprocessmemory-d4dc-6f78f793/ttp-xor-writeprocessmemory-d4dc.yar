rule TTP_XOR_WriteProcessMemory_d4dc {
  strings:
    $key_d4dc = { 83 ae [2] b1 8c [2] b7 b9 [2] 99 b9 [2] a6 a5 }

  condition:
    any of them
}