rule TTP_XOR_WriteProcessMemory_f0b5 {
  strings:
    $key_f0b5 = { a7 c7 [2] 95 e5 [2] 93 d0 [2] bd d0 [2] 82 cc }

  condition:
    any of them
}