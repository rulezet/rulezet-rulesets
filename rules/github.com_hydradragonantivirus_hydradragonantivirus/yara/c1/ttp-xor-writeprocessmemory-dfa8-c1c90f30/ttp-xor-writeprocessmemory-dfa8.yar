rule TTP_XOR_WriteProcessMemory_dfa8 {
  strings:
    $key_dfa8 = { 88 da [2] ba f8 [2] bc cd [2] 92 cd [2] ad d1 }

  condition:
    any of them
}