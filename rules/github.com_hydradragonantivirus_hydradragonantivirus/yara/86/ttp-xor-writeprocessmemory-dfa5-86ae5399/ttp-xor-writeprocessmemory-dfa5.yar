rule TTP_XOR_WriteProcessMemory_dfa5 {
  strings:
    $key_dfa5 = { 88 d7 [2] ba f5 [2] bc c0 [2] 92 c0 [2] ad dc }

  condition:
    any of them
}