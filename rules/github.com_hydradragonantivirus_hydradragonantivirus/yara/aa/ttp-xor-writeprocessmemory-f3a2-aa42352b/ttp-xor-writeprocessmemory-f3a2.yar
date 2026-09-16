rule TTP_XOR_WriteProcessMemory_f3a2 {
  strings:
    $key_f3a2 = { a4 d0 [2] 96 f2 [2] 90 c7 [2] be c7 [2] 81 db }

  condition:
    any of them
}