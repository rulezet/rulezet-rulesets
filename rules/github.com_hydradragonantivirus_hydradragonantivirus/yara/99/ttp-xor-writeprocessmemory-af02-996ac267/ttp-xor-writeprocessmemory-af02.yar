rule TTP_XOR_WriteProcessMemory_af02 {
  strings:
    $key_af02 = { f8 70 [2] ca 52 [2] cc 67 [2] e2 67 [2] dd 7b }

  condition:
    any of them
}