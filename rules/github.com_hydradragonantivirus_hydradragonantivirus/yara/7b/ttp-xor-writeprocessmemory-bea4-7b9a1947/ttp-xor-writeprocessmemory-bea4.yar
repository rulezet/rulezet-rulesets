rule TTP_XOR_WriteProcessMemory_bea4 {
  strings:
    $key_bea4 = { e9 d6 [2] db f4 [2] dd c1 [2] f3 c1 [2] cc dd }

  condition:
    any of them
}