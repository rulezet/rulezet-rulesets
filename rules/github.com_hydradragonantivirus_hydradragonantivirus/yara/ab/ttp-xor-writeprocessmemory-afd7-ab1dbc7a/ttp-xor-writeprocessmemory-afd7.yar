rule TTP_XOR_WriteProcessMemory_afd7 {
  strings:
    $key_afd7 = { f8 a5 [2] ca 87 [2] cc b2 [2] e2 b2 [2] dd ae }

  condition:
    any of them
}