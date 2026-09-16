rule TTP_XOR_WriteProcessMemory_f5dc {
  strings:
    $key_f5dc = { a2 ae [2] 90 8c [2] 96 b9 [2] b8 b9 [2] 87 a5 }

  condition:
    any of them
}