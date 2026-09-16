rule TTP_XOR_WriteProcessMemory_af77 {
  strings:
    $key_af77 = { f8 05 [2] ca 27 [2] cc 12 [2] e2 12 [2] dd 0e }

  condition:
    any of them
}