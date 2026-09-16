rule TTP_XOR_WriteProcessMemory_f381 {
  strings:
    $key_f381 = { a4 f3 [2] 96 d1 [2] 90 e4 [2] be e4 [2] 81 f8 }

  condition:
    any of them
}