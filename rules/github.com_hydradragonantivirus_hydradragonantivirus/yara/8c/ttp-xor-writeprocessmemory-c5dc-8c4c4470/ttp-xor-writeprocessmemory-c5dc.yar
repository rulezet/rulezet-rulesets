rule TTP_XOR_WriteProcessMemory_c5dc {
  strings:
    $key_c5dc = { 92 ae [2] a0 8c [2] a6 b9 [2] 88 b9 [2] b7 a5 }

  condition:
    any of them
}