rule TTP_XOR_WriteProcessMemory_f0dc {
  strings:
    $key_f0dc = { a7 ae [2] 95 8c [2] 93 b9 [2] bd b9 [2] 82 a5 }

  condition:
    any of them
}