rule TTP_XOR_WriteProcessMemory_af43 {
  strings:
    $key_af43 = { f8 31 [2] ca 13 [2] cc 26 [2] e2 26 [2] dd 3a }

  condition:
    any of them
}