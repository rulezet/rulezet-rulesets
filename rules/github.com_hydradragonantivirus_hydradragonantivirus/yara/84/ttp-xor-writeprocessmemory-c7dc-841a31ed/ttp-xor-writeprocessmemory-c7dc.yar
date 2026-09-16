rule TTP_XOR_WriteProcessMemory_c7dc {
  strings:
    $key_c7dc = { 90 ae [2] a2 8c [2] a4 b9 [2] 8a b9 [2] b5 a5 }

  condition:
    any of them
}