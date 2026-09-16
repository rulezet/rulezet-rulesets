rule TTP_XOR_WriteProcessMemory_a9b0 {
  strings:
    $key_a9b0 = { fe c2 [2] cc e0 [2] ca d5 [2] e4 d5 [2] db c9 }

  condition:
    any of them
}