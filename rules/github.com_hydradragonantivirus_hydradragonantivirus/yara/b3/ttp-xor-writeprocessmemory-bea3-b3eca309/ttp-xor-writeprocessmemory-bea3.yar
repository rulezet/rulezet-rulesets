rule TTP_XOR_WriteProcessMemory_bea3 {
  strings:
    $key_bea3 = { e9 d1 [2] db f3 [2] dd c6 [2] f3 c6 [2] cc da }

  condition:
    any of them
}