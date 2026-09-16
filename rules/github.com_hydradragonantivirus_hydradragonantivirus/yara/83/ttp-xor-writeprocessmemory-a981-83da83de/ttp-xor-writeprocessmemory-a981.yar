rule TTP_XOR_WriteProcessMemory_a981 {
  strings:
    $key_a981 = { fe f3 [2] cc d1 [2] ca e4 [2] e4 e4 [2] db f8 }

  condition:
    any of them
}