rule TTP_XOR_WriteProcessMemory_f3a9 {
  strings:
    $key_f3a9 = { a4 db [2] 96 f9 [2] 90 cc [2] be cc [2] 81 d0 }

  condition:
    any of them
}