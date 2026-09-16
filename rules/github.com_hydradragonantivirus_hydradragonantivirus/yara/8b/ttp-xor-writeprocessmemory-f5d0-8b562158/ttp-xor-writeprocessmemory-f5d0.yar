rule TTP_XOR_WriteProcessMemory_f5d0 {
  strings:
    $key_f5d0 = { a2 a2 [2] 90 80 [2] 96 b5 [2] b8 b5 [2] 87 a9 }

  condition:
    any of them
}