rule TTP_XOR_WriteProcessMemory_a980 {
  strings:
    $key_a980 = { fe f2 [2] cc d0 [2] ca e5 [2] e4 e5 [2] db f9 }

  condition:
    any of them
}