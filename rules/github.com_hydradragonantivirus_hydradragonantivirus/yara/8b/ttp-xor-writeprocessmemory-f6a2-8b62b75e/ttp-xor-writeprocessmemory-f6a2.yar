rule TTP_XOR_WriteProcessMemory_f6a2 {
  strings:
    $key_f6a2 = { a1 d0 [2] 93 f2 [2] 95 c7 [2] bb c7 [2] 84 db }

  condition:
    any of them
}