rule TTP_XOR_WriteProcessMemory_5580 {
  strings:
    $key_5580 = { 02 f2 [2] 30 d0 [2] 36 e5 [2] 18 e5 [2] 27 f9 }

  condition:
    any of them
}