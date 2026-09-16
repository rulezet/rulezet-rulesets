rule TTP_XOR_WriteProcessMemory_af30 {
  strings:
    $key_af30 = { f8 42 [2] ca 60 [2] cc 55 [2] e2 55 [2] dd 49 }

  condition:
    any of them
}