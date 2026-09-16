rule TTP_XOR_WriteProcessMemory_1480 {
  strings:
    $key_1480 = { 43 f2 [2] 71 d0 [2] 77 e5 [2] 59 e5 [2] 66 f9 }

  condition:
    any of them
}