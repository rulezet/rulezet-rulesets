rule TTP_XOR_WriteProcessMemory_f082 {
  strings:
    $key_f082 = { a7 f0 [2] 95 d2 [2] 93 e7 [2] bd e7 [2] 82 fb }

  condition:
    any of them
}