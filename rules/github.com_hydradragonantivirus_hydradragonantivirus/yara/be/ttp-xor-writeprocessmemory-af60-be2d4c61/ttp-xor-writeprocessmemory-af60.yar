rule TTP_XOR_WriteProcessMemory_af60 {
  strings:
    $key_af60 = { f8 12 [2] ca 30 [2] cc 05 [2] e2 05 [2] dd 19 }

  condition:
    any of them
}