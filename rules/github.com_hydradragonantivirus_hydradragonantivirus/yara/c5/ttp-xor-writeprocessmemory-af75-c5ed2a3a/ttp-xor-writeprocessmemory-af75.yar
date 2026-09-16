rule TTP_XOR_WriteProcessMemory_af75 {
  strings:
    $key_af75 = { f8 07 [2] ca 25 [2] cc 10 [2] e2 10 [2] dd 0c }

  condition:
    any of them
}