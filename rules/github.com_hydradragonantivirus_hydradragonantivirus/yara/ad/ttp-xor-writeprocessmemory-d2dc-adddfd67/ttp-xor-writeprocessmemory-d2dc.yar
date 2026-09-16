rule TTP_XOR_WriteProcessMemory_d2dc {
  strings:
    $key_d2dc = { 85 ae [2] b7 8c [2] b1 b9 [2] 9f b9 [2] a0 a5 }

  condition:
    any of them
}