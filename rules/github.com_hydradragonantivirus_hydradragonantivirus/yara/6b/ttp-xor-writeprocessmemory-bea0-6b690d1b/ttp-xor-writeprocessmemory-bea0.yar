rule TTP_XOR_WriteProcessMemory_bea0 {
  strings:
    $key_bea0 = { e9 d2 [2] db f0 [2] dd c5 [2] f3 c5 [2] cc d9 }

  condition:
    any of them
}