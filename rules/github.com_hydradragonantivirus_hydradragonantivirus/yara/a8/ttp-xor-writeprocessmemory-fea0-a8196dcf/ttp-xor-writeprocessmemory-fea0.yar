rule TTP_XOR_WriteProcessMemory_fea0 {
  strings:
    $key_fea0 = { a9 d2 [2] 9b f0 [2] 9d c5 [2] b3 c5 [2] 8c d9 }

  condition:
    any of them
}