rule TTP_XOR_WriteProcessMemory_af65 {
  strings:
    $key_af65 = { f8 17 [2] ca 35 [2] cc 00 [2] e2 00 [2] dd 1c }

  condition:
    any of them
}