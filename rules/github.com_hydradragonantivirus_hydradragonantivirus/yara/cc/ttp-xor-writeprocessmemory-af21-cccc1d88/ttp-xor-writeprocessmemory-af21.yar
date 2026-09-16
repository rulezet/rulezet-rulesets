rule TTP_XOR_WriteProcessMemory_af21 {
  strings:
    $key_af21 = { f8 53 [2] ca 71 [2] cc 44 [2] e2 44 [2] dd 58 }

  condition:
    any of them
}