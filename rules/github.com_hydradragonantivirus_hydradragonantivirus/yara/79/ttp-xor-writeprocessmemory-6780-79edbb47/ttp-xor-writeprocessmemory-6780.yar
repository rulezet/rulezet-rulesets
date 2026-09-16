rule TTP_XOR_WriteProcessMemory_6780 {
  strings:
    $key_6780 = { 30 f2 [2] 02 d0 [2] 04 e5 [2] 2a e5 [2] 15 f9 }

  condition:
    any of them
}