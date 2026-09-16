rule TTP_XOR_WriteProcessMemory_d6dc {
  strings:
    $key_d6dc = { 81 ae [2] b3 8c [2] b5 b9 [2] 9b b9 [2] a4 a5 }

  condition:
    any of them
}