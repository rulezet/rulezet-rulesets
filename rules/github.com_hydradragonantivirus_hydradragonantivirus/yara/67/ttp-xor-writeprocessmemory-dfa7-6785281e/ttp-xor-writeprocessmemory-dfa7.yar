rule TTP_XOR_WriteProcessMemory_dfa7 {
  strings:
    $key_dfa7 = { 88 d5 [2] ba f7 [2] bc c2 [2] 92 c2 [2] ad de }

  condition:
    any of them
}