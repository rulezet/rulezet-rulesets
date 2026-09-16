rule TTP_XOR_WriteProcessMemory_af70 {
  strings:
    $key_af70 = { f8 02 [2] ca 20 [2] cc 15 [2] e2 15 [2] dd 09 }

  condition:
    any of them
}