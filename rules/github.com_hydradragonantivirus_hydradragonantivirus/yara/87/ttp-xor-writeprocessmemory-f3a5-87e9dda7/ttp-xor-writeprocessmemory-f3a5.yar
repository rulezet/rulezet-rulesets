rule TTP_XOR_WriteProcessMemory_f3a5 {
  strings:
    $key_f3a5 = { a4 d7 [2] 96 f5 [2] 90 c0 [2] be c0 [2] 81 dc }

  condition:
    any of them
}