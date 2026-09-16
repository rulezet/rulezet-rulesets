rule TTP_XOR_WriteProcessMemory_f7b5 {
  strings:
    $key_f7b5 = { a0 c7 [2] 92 e5 [2] 94 d0 [2] ba d0 [2] 85 cc }

  condition:
    any of them
}