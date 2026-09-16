rule TTP_XOR_WriteProcessMemory_af20 {
  strings:
    $key_af20 = { f8 52 [2] ca 70 [2] cc 45 [2] e2 45 [2] dd 59 }

  condition:
    any of them
}