rule TTP_XOR_WriteProcessMemory_af56 {
  strings:
    $key_af56 = { f8 24 [2] ca 06 [2] cc 33 [2] e2 33 [2] dd 2f }

  condition:
    any of them
}