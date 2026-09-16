rule TTP_XOR_WriteProcessMemory_af35 {
  strings:
    $key_af35 = { f8 47 [2] ca 65 [2] cc 50 [2] e2 50 [2] dd 4c }

  condition:
    any of them
}