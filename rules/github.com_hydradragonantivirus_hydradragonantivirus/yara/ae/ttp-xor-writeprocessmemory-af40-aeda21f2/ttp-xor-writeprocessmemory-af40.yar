rule TTP_XOR_WriteProcessMemory_af40 {
  strings:
    $key_af40 = { f8 32 [2] ca 10 [2] cc 25 [2] e2 25 [2] dd 39 }

  condition:
    any of them
}