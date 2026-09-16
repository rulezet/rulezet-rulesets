rule TTP_XOR_WriteProcessMemory_c2dc {
  strings:
    $key_c2dc = { 95 ae [2] a7 8c [2] a1 b9 [2] 8f b9 [2] b0 a5 }

  condition:
    any of them
}