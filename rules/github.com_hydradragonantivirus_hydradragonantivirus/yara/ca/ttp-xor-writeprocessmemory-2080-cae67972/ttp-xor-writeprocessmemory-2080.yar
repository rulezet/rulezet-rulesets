rule TTP_XOR_WriteProcessMemory_2080 {
  strings:
    $key_2080 = { 77 f2 [2] 45 d0 [2] 43 e5 [2] 6d e5 [2] 52 f9 }

  condition:
    any of them
}