rule TTP_XOR_WriteProcessMemory_f7e1 {
  strings:
    $key_f7e1 = { a0 93 [2] 92 b1 [2] 94 84 [2] ba 84 [2] 85 98 }

  condition:
    any of them
}