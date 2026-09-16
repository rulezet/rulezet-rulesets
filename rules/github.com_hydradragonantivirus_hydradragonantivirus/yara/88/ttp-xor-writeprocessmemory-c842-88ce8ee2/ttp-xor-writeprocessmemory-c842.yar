rule TTP_XOR_WriteProcessMemory_c842 {
  strings:
    $key_c842 = { 9f 30 [2] ad 12 [2] ab 27 [2] 85 27 [2] ba 3b }

  condition:
    any of them
}