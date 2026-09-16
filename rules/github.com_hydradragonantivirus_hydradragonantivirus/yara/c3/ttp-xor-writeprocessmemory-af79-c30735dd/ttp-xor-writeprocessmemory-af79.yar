rule TTP_XOR_WriteProcessMemory_af79 {
  strings:
    $key_af79 = { f8 0b [2] ca 29 [2] cc 1c [2] e2 1c [2] dd 00 }

  condition:
    any of them
}