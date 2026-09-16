rule TTP_XOR_WriteProcessMemory_af45 {
  strings:
    $key_af45 = { f8 37 [2] ca 15 [2] cc 20 [2] e2 20 [2] dd 3c }

  condition:
    any of them
}