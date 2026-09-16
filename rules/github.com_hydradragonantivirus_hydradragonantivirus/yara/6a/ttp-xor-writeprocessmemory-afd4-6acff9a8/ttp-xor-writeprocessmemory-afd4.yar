rule TTP_XOR_WriteProcessMemory_afd4 {
  strings:
    $key_afd4 = { f8 a6 [2] ca 84 [2] cc b1 [2] e2 b1 [2] dd ad }

  condition:
    any of them
}