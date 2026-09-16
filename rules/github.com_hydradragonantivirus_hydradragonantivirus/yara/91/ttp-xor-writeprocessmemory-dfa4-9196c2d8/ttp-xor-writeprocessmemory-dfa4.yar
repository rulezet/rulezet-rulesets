rule TTP_XOR_WriteProcessMemory_dfa4 {
  strings:
    $key_dfa4 = { 88 d6 [2] ba f4 [2] bc c1 [2] 92 c1 [2] ad dd }

  condition:
    any of them
}