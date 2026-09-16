rule TTP_XOR_WriteProcessMemory_dfa1 {
  strings:
    $key_dfa1 = { 88 d3 [2] ba f1 [2] bc c4 [2] 92 c4 [2] ad d8 }

  condition:
    any of them
}