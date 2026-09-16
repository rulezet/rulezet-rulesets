rule TTP_XOR_WriteProcessMemory_a9b4 {
  strings:
    $key_a9b4 = { fe c6 [2] cc e4 [2] ca d1 [2] e4 d1 [2] db cd }

  condition:
    any of them
}