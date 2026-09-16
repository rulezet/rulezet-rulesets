rule TTP_XOR_WriteProcessMemory_c6dc {
  strings:
    $key_c6dc = { 91 ae [2] a3 8c [2] a5 b9 [2] 8b b9 [2] b4 a5 }

  condition:
    any of them
}